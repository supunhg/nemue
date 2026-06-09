// Memory pool allocator for efficient packet handling
use std::sync::Arc;
use tokio::sync::Mutex;
use std::collections::VecDeque;

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
            if let Some(mut pool) = pool.try_lock().ok() {
                pool.return_buffer(buf);
            }
        }
    }
}

/// Memory pool for buffer reuse
pub struct BufferPool {
    buffers: VecDeque<Vec<u8>>,
    buffer_size: usize,
    max_pool_size: usize,
}

impl BufferPool {
    pub fn new(buffer_size: usize, initial_capacity: usize, max_pool_size: usize) -> Arc<Mutex<Self>> {
        let mut buffers = VecDeque::with_capacity(initial_capacity);
        for _ in 0..initial_capacity {
            buffers.push_back(vec![0u8; buffer_size]);
        }

        Arc::new(Mutex::new(Self {
            buffers,
            buffer_size,
            max_pool_size,
        }))
    }

    pub async fn acquire(pool: Arc<Mutex<Self>>) -> PooledBuffer {
        let data = {
            let mut pool_guard = pool.lock().await;
            pool_guard.buffers.pop_front().unwrap_or_else(|| {
                vec![0u8; pool_guard.buffer_size]
            })
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
}
