// Worker pool for parallel task processing
use std::sync::Arc;
use tokio::sync::{mpsc, Semaphore};
use tokio::task::JoinHandle;

pub type Task = Box<dyn FnOnce() -> () + Send + 'static>;

pub struct WorkerPool {
    workers: Vec<Worker>,
    sender: mpsc::UnboundedSender<Task>,
}

impl WorkerPool {
    pub fn new(size: usize) -> Self {
        let (sender, receiver) = mpsc::unbounded_channel::<Task>();
        let receiver = Arc::new(tokio::sync::Mutex::new(receiver));
        
        let mut workers = Vec::with_capacity(size);
        for id in 0..size {
            workers.push(Worker::new(id, Arc::clone(&receiver)));
        }

        Self { workers, sender }
    }

    pub fn execute<F>(&self, f: F) 
    where
        F: FnOnce() -> () + Send + 'static,
    {
        let job = Box::new(f);
        self.sender.send(job).expect("Failed to send job");
    }

    pub fn size(&self) -> usize {
        self.workers.len()
    }
}

struct Worker {
    id: usize,
    handle: Option<JoinHandle<()>>,
}

impl Worker {
    fn new(id: usize, receiver: Arc<tokio::sync::Mutex<mpsc::UnboundedReceiver<Task>>>) -> Self {
        let handle = tokio::spawn(async move {
            loop {
                let task = {
                    let mut receiver = receiver.lock().await;
                    receiver.recv().await
                };

                match task {
                    Some(task) => task(),
                    None => break,
                }
            }
        });

        Self {
            id,
            handle: Some(handle),
        }
    }
}

/// Semaphore-based concurrency limiter
pub struct ConcurrencyLimiter {
    semaphore: Arc<Semaphore>,
}

impl ConcurrencyLimiter {
    pub fn new(max_concurrent: usize) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(max_concurrent)),
        }
    }

    pub async fn acquire(&self) -> Result<tokio::sync::SemaphorePermit, String> {
        self.semaphore
            .acquire()
            .await
            .map_err(|e| format!("Failed to acquire permit: {}", e))
    }

    pub fn available_permits(&self) -> usize {
        self.semaphore.available_permits()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn test_worker_pool_creation() {
        let pool = WorkerPool::new(4);
        assert_eq!(pool.size(), 4);
    }

    #[tokio::test]
    async fn test_worker_pool_execute() {
        let pool = WorkerPool::new(2);
        let counter = Arc::new(AtomicUsize::new(0));
        
        for _ in 0..10 {
            let counter_clone = Arc::clone(&counter);
            pool.execute(move || {
                counter_clone.fetch_add(1, Ordering::Relaxed);
            });
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        assert_eq!(counter.load(Ordering::Relaxed), 10);
    }

    #[tokio::test]
    async fn test_concurrency_limiter() {
        let limiter = ConcurrencyLimiter::new(3);
        assert_eq!(limiter.available_permits(), 3);

        let _permit1 = limiter.acquire().await.unwrap();
        assert_eq!(limiter.available_permits(), 2);

        let _permit2 = limiter.acquire().await.unwrap();
        assert_eq!(limiter.available_permits(), 1);

        let _permit3 = limiter.acquire().await.unwrap();
        assert_eq!(limiter.available_permits(), 0);
    }

    #[tokio::test]
    async fn test_concurrency_limiter_release() {
        let limiter = ConcurrencyLimiter::new(2);
        
        {
            let _permit = limiter.acquire().await.unwrap();
            assert_eq!(limiter.available_permits(), 1);
        }
        
        // Permit should be released
        assert_eq!(limiter.available_permits(), 2);
    }
}
