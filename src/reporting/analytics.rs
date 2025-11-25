// Advanced analytics for vulnerability prediction and risk modeling
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyticsEngine {
    pub risk_model: RiskModel,
    pub predictions: Vec<Prediction>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskModel {
    pub model_type: ModelType,
    pub parameters: HashMap<String, f64>,
    pub accuracy: f64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ModelType {
    Bayesian,
    WeightedScore,
    MachineLearning,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Prediction {
    pub target: String,
    pub probability: f64,
    pub confidence: f64,
    pub risk_factors: Vec<RiskFactor>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFactor {
    pub name: String,
    pub weight: f64,
    pub value: f64,
    pub contribution: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityPrediction {
    pub host: String,
    pub service: String,
    pub predicted_vulnerabilities: Vec<PredictedVulnerability>,
    pub overall_risk: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PredictedVulnerability {
    pub vulnerability_type: String,
    pub probability: f64,
    pub severity: f64,
    pub time_to_exploit: Option<u64>,
}

impl AnalyticsEngine {
    pub fn new(model_type: ModelType) -> Self {
        Self {
            risk_model: RiskModel {
                model_type,
                parameters: HashMap::new(),
                accuracy: 0.0,
            },
            predictions: Vec::new(),
        }
    }

    pub fn calculate_risk_score(&self, factors: &[RiskFactor]) -> f64 {
        match self.risk_model.model_type {
            ModelType::WeightedScore => {
                factors.iter()
                    .map(|f| f.weight * f.value)
                    .sum::<f64>()
                    / factors.iter().map(|f| f.weight).sum::<f64>()
            }
            ModelType::Bayesian => {
                // Simplified Bayesian approach
                let prior = 0.5;
                let likelihood: f64 = factors.iter()
                    .map(|f| f.value * f.weight)
                    .product();
                (prior * likelihood) / (prior * likelihood + (1.0 - prior) * (1.0 - likelihood))
            }
            ModelType::MachineLearning => {
                // Placeholder for ML model
                factors.iter()
                    .map(|f| f.contribution)
                    .sum::<f64>()
            }
        }
    }

    pub fn predict_vulnerability(&self, host: &str, service: &str, historical_data: &[f64]) -> VulnerabilityPrediction {
        let avg_severity = if historical_data.is_empty() {
            5.0
        } else {
            historical_data.iter().sum::<f64>() / historical_data.len() as f64
        };

        let predicted_vulns = vec![
            PredictedVulnerability {
                vulnerability_type: "Configuration Weakness".to_string(),
                probability: 0.65,
                severity: avg_severity * 0.8,
                time_to_exploit: Some(7),
            },
            PredictedVulnerability {
                vulnerability_type: "Outdated Software".to_string(),
                probability: 0.45,
                severity: avg_severity * 1.2,
                time_to_exploit: Some(14),
            },
        ];

        let overall_risk = predicted_vulns.iter()
            .map(|v| v.probability * v.severity)
            .sum::<f64>()
            / predicted_vulns.len() as f64;

        VulnerabilityPrediction {
            host: host.to_string(),
            service: service.to_string(),
            predicted_vulnerabilities: predicted_vulns,
            overall_risk,
        }
    }

    pub fn add_prediction(&mut self, prediction: Prediction) {
        self.predictions.push(prediction);
    }

    pub fn set_parameter(&mut self, key: &str, value: f64) {
        self.risk_model.parameters.insert(key.to_string(), value);
    }

    pub fn set_accuracy(&mut self, accuracy: f64) {
        self.risk_model.accuracy = accuracy.clamp(0.0, 1.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analytics_engine_creation() {
        let engine = AnalyticsEngine::new(ModelType::WeightedScore);
        assert_eq!(engine.risk_model.model_type, ModelType::WeightedScore);
        assert_eq!(engine.predictions.len(), 0);
    }

    #[test]
    fn test_weighted_score_calculation() {
        let engine = AnalyticsEngine::new(ModelType::WeightedScore);
        
        let factors = vec![
            RiskFactor {
                name: "Severity".to_string(),
                weight: 0.5,
                value: 8.0,
                contribution: 0.0,
            },
            RiskFactor {
                name: "Exploitability".to_string(),
                weight: 0.3,
                value: 6.0,
                contribution: 0.0,
            },
            RiskFactor {
                name: "Impact".to_string(),
                weight: 0.2,
                value: 9.0,
                contribution: 0.0,
            },
        ];

        let score = engine.calculate_risk_score(&factors);
        assert!(score > 0.0 && score <= 10.0);
    }

    #[test]
    fn test_bayesian_calculation() {
        let engine = AnalyticsEngine::new(ModelType::Bayesian);
        
        let factors = vec![
            RiskFactor {
                name: "Factor1".to_string(),
                weight: 0.6,
                value: 0.8,
                contribution: 0.0,
            },
        ];

        let score = engine.calculate_risk_score(&factors);
        assert!(score >= 0.0 && score <= 1.0);
    }

    #[test]
    fn test_vulnerability_prediction() {
        let engine = AnalyticsEngine::new(ModelType::WeightedScore);
        
        let historical_data = vec![6.0, 7.5, 8.0];
        let prediction = engine.predict_vulnerability("192.168.1.10", "http", &historical_data);

        assert_eq!(prediction.host, "192.168.1.10");
        assert_eq!(prediction.service, "http");
        assert_eq!(prediction.predicted_vulnerabilities.len(), 2);
        assert!(prediction.overall_risk > 0.0);
    }

    #[test]
    fn test_add_prediction() {
        let mut engine = AnalyticsEngine::new(ModelType::WeightedScore);
        
        let prediction = Prediction {
            target: "web-server".to_string(),
            probability: 0.75,
            confidence: 0.85,
            risk_factors: vec![],
        };

        engine.add_prediction(prediction);
        assert_eq!(engine.predictions.len(), 1);
    }

    #[test]
    fn test_set_parameter() {
        let mut engine = AnalyticsEngine::new(ModelType::WeightedScore);
        
        engine.set_parameter("threshold", 7.5);
        assert_eq!(engine.risk_model.parameters.get("threshold"), Some(&7.5));
    }

    #[test]
    fn test_set_accuracy() {
        let mut engine = AnalyticsEngine::new(ModelType::WeightedScore);
        
        engine.set_accuracy(0.92);
        assert_eq!(engine.risk_model.accuracy, 0.92);
        
        engine.set_accuracy(1.5);
        assert_eq!(engine.risk_model.accuracy, 1.0);
        
        engine.set_accuracy(-0.5);
        assert_eq!(engine.risk_model.accuracy, 0.0);
    }

    #[test]
    fn test_risk_factor() {
        let factor = RiskFactor {
            name: "Test".to_string(),
            weight: 0.5,
            value: 8.0,
            contribution: 4.0,
        };

        assert_eq!(factor.weight, 0.5);
        assert_eq!(factor.value, 8.0);
    }

    #[test]
    fn test_predicted_vulnerability() {
        let vuln = PredictedVulnerability {
            vulnerability_type: "SQL Injection".to_string(),
            probability: 0.65,
            severity: 8.5,
            time_to_exploit: Some(3),
        };

        assert_eq!(vuln.vulnerability_type, "SQL Injection");
        assert_eq!(vuln.time_to_exploit, Some(3));
    }

    #[test]
    fn test_model_types() {
        assert_ne!(ModelType::Bayesian, ModelType::WeightedScore);
        assert_ne!(ModelType::WeightedScore, ModelType::MachineLearning);
    }
}
