// Memory pool allocator for efficient packet handling
use std::sync::Arc;
use tokio::sync::Mutex;
use std::collections::VecDeque;

/// Reusable buffer from the pool
pub struct PooledBuffer {
    data: Vec<u8>,
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

    pub fn acquire(pool: Arc<Mutex<Self>>) -> PooledBuffer {
        let data = {
            let mut pool_guard = pool.try_lock().unwrap_or_else(|_| {
                std::thread::sleep(std::time::Duration::from_micros(10));
                pool.blocking_lock()
            });
            
            pool_guard.buffers.pop_front().unwrap_or_else(|| {
                vec![0u8; pool_guard.buffer_size]
            })
        };

        PooledBuffer { data }
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

/// Connection pool for reusing TCP/UDP connections
pub struct ConnectionPool<T> {
    connections: Arc<Mutex<VecDeque<T>>>,
    max_size: usize,
}

impl<T> ConnectionPool<T> {
    pub fn new(max_size: usize) -> Self {
        Self {
            connections: Arc::new(Mutex::new(VecDeque::with_capacity(max_size))),
            max_size,
        }
    }

    pub async fn acquire(&self) -> Option<T> {
        self.connections.lock().await.pop_front()
    }

    pub async fn release(&self, conn: T) {
        let mut conns = self.connections.lock().await;
        if conns.len() < self.max_size {
            conns.push_back(conn);
        }
    }

    pub async fn size(&self) -> usize {
        self.connections.lock().await.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_buffer_pool_creation() {
        let pool = BufferPool::new(1024, 10, 100);
        let pool_guard = pool.blocking_lock();
        assert_eq!(pool_guard.pool_size(), 10);
    }

    #[test]
    fn test_buffer_acquire() {
        let pool = BufferPool::new(1024, 10, 100);
        let buffer = BufferPool::acquire(pool.clone());
        assert_eq!(buffer.len(), 1024);
    }

    #[test]
    fn test_buffer_pool_reuse() {
        let pool = BufferPool::new(1024, 5, 100);
        {
            let _buffer = BufferPool::acquire(pool.clone());
            assert_eq!(pool.blocking_lock().pool_size(), 4);
        }
        // Buffer should be returned after drop
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    #[tokio::test]
    async fn test_connection_pool() {
        let pool: ConnectionPool<String> = ConnectionPool::new(10);
        
        pool.release("conn1".to_string()).await;
        pool.release("conn2".to_string()).await;
        
        assert_eq!(pool.size().await, 2);
        
        let conn = pool.acquire().await;
        assert!(conn.is_some());
        assert_eq!(pool.size().await, 1);
    }

    #[tokio::test]
    async fn test_connection_pool_max_size() {
        let pool: ConnectionPool<u32> = ConnectionPool::new(2);
        
        pool.release(1).await;
        pool.release(2).await;
        pool.release(3).await; // Should be dropped
        
        assert_eq!(pool.size().await, 2);
    }
}
