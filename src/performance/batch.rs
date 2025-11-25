// Batch processing for system calls
use std::time::Duration;
use tokio::time::interval;
use tokio::sync::mpsc;

pub struct BatchProcessor<T> {
    batch_size: usize,
    flush_interval: Duration,
    sender: mpsc::UnboundedSender<T>,
}

impl<T: Send + 'static> BatchProcessor<T> {
    pub fn new<F>(batch_size: usize, flush_interval: Duration, handler: F) -> Self
    where
        F: Fn(Vec<T>) + Send + 'static,
    {
        let (sender, mut receiver) = mpsc::unbounded_channel::<T>();

        tokio::spawn(async move {
            let mut batch = Vec::with_capacity(batch_size);
            let mut timer = interval(flush_interval);
            timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                tokio::select! {
                    Some(item) = receiver.recv() => {
                        batch.push(item);
                        if batch.len() >= batch_size {
                            let to_process = std::mem::replace(&mut batch, Vec::with_capacity(batch_size));
                            handler(to_process);
                        }
                    }
                    _ = timer.tick() => {
                        if !batch.is_empty() {
                            let to_process = std::mem::replace(&mut batch, Vec::with_capacity(batch_size));
                            handler(to_process);
                        }
                    }
                }
            }
        });

        Self {
            batch_size,
            flush_interval,
            sender,
        }
    }

    pub fn push(&self, item: T) -> Result<(), String> {
        self.sender
            .send(item)
            .map_err(|_| "Channel closed".to_string())
    }

    pub fn batch_size(&self) -> usize {
        self.batch_size
    }

    pub fn flush_interval(&self) -> Duration {
        self.flush_interval
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[tokio::test]
    async fn test_batch_size_trigger() {
        let processed = Arc::new(Mutex::new(Vec::new()));
        let processed_clone = Arc::clone(&processed);

        let processor = BatchProcessor::new(3, Duration::from_secs(10), move |batch| {
            processed_clone.lock().unwrap().extend(batch);
        });

        for i in 0..3 {
            processor.push(i).unwrap();
        }

        tokio::time::sleep(Duration::from_millis(50)).await;

        let result = processed.lock().unwrap().clone();
        assert_eq!(result, vec![0, 1, 2]);
    }

    #[tokio::test]
    async fn test_time_trigger() {
        let processed = Arc::new(Mutex::new(Vec::new()));
        let processed_clone = Arc::clone(&processed);

        let processor = BatchProcessor::new(10, Duration::from_millis(100), move |batch| {
            processed_clone.lock().unwrap().extend(batch);
        });

        processor.push(1).unwrap();
        processor.push(2).unwrap();

        tokio::time::sleep(Duration::from_millis(150)).await;

        let result = processed.lock().unwrap().clone();
        assert_eq!(result, vec![1, 2]);
    }

    #[tokio::test]
    async fn test_multiple_batches() {
        let processed = Arc::new(Mutex::new(Vec::new()));
        let processed_clone = Arc::clone(&processed);

        let processor = BatchProcessor::new(2, Duration::from_secs(10), move |batch| {
            processed_clone.lock().unwrap().extend(batch);
        });

        for i in 0..5 {
            processor.push(i).unwrap();
        }

        tokio::time::sleep(Duration::from_millis(100)).await;

        let result = processed.lock().unwrap().clone();
        // Two full batches of 2 = 4 items processed, 1 item remains in buffer
        assert!(result.len() >= 4 && result.len() <= 5);
    }

    #[tokio::test]
    async fn test_batch_processor_config() {
        let processor = BatchProcessor::new(5, Duration::from_millis(200), |_batch: Vec<i32>| {});

        assert_eq!(processor.batch_size(), 5);
        assert_eq!(processor.flush_interval(), Duration::from_millis(200));
    }
}
