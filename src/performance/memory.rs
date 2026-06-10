// Memory pool allocator for efficient packet handling
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::Mutex;

// Common packet sizes for pre-allocation: TCP header(20), Ethernet MTU(1500), etc.
const COMMON_SIZES: &[usize] = &[40, 64, 128, 256, 512, 1500];

/// Reusable buffer from the pool - returns to pool on drop
pub struct PooledBuffer {
    data: Vec<u8>,
    pool: Option<Arc<Mutex<BufferPool>>>,
}

impl PooledBuffer {
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl Drop for PooledBuffer {
    fn drop(&mut self) {
        if let Some(pool) = self.pool.take() {
            let buf = std::mem::take(&mut self.data);
            // Best-effort return to pool; if lock is contended, buffer is dropped
            if let Ok(mut pool) = pool.try_lock() {
                pool.return_buffer(buf);
            }
        }
    }
}

/// Memory pool statistics
#[derive(Debug, Clone)]
pub struct PoolStats {
    pub available_buffers: usize,
    pub hits: u64,
    pub misses: u64,
    pub hit_rate: f64,
}

/// Memory pool for buffer reuse with pre-allocation for common packet sizes
pub struct BufferPool {
    buffers: VecDeque<Vec<u8>>,
    buffer_size: usize,
    max_pool_size: usize,
    hits: AtomicU64,
    misses: AtomicU64,
}

impl BufferPool {
    pub fn new(
        buffer_size: usize,
        initial_capacity: usize,
        max_pool_size: usize,
    ) -> Arc<Mutex<Self>> {
        let mut buffers = VecDeque::with_capacity(initial_capacity);
        for _ in 0..initial_capacity {
            buffers.push_back(vec![0u8; buffer_size]);
        }

        Arc::new(Mutex::new(Self {
            buffers,
            buffer_size,
            max_pool_size,
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }))
    }

    /// Create a buffer pool pre-seeded with common packet sizes
    pub fn with_common_sizes(initial_per_size: usize, max_pool_size: usize) -> Arc<Mutex<Self>> {
        let total_initial = initial_per_size * COMMON_SIZES.len();
        let mut buffers = VecDeque::with_capacity(total_initial);

        // Pre-allocate buffers for each common size
        for &size in COMMON_SIZES {
            for _ in 0..initial_per_size {
                buffers.push_back(vec![0u8; size]);
            }
        }

        // Use 1500 (MTU) as the default buffer size since it's the most common
        Arc::new(Mutex::new(Self {
            buffers,
            buffer_size: 1500,
            max_pool_size,
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }))
    }

    pub async fn acquire(pool: Arc<Mutex<Self>>) -> PooledBuffer {
        let data = {
            let mut pool_guard = pool.lock().await;
            let buf = pool_guard.buffers.pop_front();
            if buf.is_some() {
                pool_guard.hits.fetch_add(1, Ordering::Relaxed);
                buf.unwrap()
            } else {
                pool_guard.misses.fetch_add(1, Ordering::Relaxed);
                vec![0u8; pool_guard.buffer_size]
            }
        };

        PooledBuffer {
            data,
            pool: Some(pool),
        }
    }

    /// Acquire a buffer of a specific size, trying to find a close match first
    pub async fn acquire_sized(pool: Arc<Mutex<Self>>, min_size: usize) -> PooledBuffer {
        let data = {
            let mut pool_guard = pool.lock().await;
            // Try to find a buffer that's at least min_size
            let idx = pool_guard
                .buffers
                .iter()
                .position(|b| b.capacity() >= min_size);
            if let Some(i) = idx {
                pool_guard.hits.fetch_add(1, Ordering::Relaxed);
                let mut buf = pool_guard.buffers.remove(i).unwrap();
                buf.resize(min_size, 0);
                buf
            } else {
                pool_guard.misses.fetch_add(1, Ordering::Relaxed);
                vec![0u8; min_size]
            }
        };

        PooledBuffer {
            data,
            pool: Some(pool),
        }
    }

    fn return_buffer(&mut self, mut buffer: Vec<u8>) {
        if self.buffers.len() < self.max_pool_size {
            buffer.clear();
            buffer.resize(self.buffer_size, 0);
            self.buffers.push_back(buffer);
        }
    }

    pub fn pool_size(&self) -> usize {
        self.buffers.len()
    }

    pub fn stats(&self) -> PoolStats {
        let hits = self.hits.load(Ordering::Relaxed);
        let misses = self.misses.load(Ordering::Relaxed);
        let total = hits + misses;
        PoolStats {
            available_buffers: self.buffers.len(),
            hits,
            misses,
            hit_rate: if total > 0 {
                hits as f64 / total as f64
            } else {
                0.0
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_buffer_pool_acquire_return() {
        let pool = BufferPool::new(64, 4, 8);
        {
            let p = pool.lock().await;
            assert_eq!(p.pool_size(), 4);
        }

        let buf = BufferPool::acquire(pool.clone()).await;
        assert_eq!(buf.len(), 64);
        {
            let p = pool.lock().await;
            assert_eq!(p.pool_size(), 3);
        }
        drop(buf);

        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        {
            let p = pool.lock().await;
            assert_eq!(p.pool_size(), 4);
        }
    }

    #[tokio::test]
    async fn test_buffer_pool_reuse() {
        let pool = BufferPool::new(128, 2, 4);

        let buf1 = BufferPool::acquire(pool.clone()).await;
        let buf2 = BufferPool::acquire(pool.clone()).await;
        drop(buf1);
        drop(buf2);

        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        // Both buffers should be back in the pool
        let buf3 = BufferPool::acquire(pool.clone()).await;
        let buf4 = BufferPool::acquire(pool.clone()).await;
        assert_eq!(buf3.len(), 128);
        assert_eq!(buf4.len(), 128);
    }

    #[tokio::test]
    async fn test_buffer_pool_stats() {
        let pool = BufferPool::new(64, 4, 8);

        // Acquire 3 buffers (3 hits, 0 misses)
        let _b1 = BufferPool::acquire(pool.clone()).await;
        let _b2 = BufferPool::acquire(pool.clone()).await;
        let _b3 = BufferPool::acquire(pool.clone()).await;

        // Acquire 2 more (1 hit from pool, 1 miss creates new)
        let _b4 = BufferPool::acquire(pool.clone()).await;
        let _b5 = BufferPool::acquire(pool.clone()).await;

        let stats = {
            let p = pool.lock().await;
            p.stats()
        };
        assert_eq!(stats.hits, 4);
        assert_eq!(stats.misses, 1);
        assert!(stats.hit_rate > 0.7);
    }

    #[tokio::test]
    async fn test_buffer_pool_with_common_sizes() {
        let pool = BufferPool::with_common_sizes(2, 64);
        let stats = {
            let p = pool.lock().await;
            p.stats()
        };
        // 2 buffers per size * 6 common sizes = 12 total
        assert_eq!(stats.available_buffers, 12);

        let buf = BufferPool::acquire(pool.clone()).await;
        // First buffer should be 40 bytes (smallest common size)
        assert_eq!(buf.len(), 40);
    }
}
