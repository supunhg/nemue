// Advanced analytics: risk modeling, trend analysis, statistical analysis, comparative analysis, predictive analysis
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyticsEngine {
    pub risk_model: RiskModel,
    pub predictions: Vec<Prediction>,
    pub trend_analyses: Vec<TrendAnalysis>,
    pub comparative_results: Vec<ComparativeResult>,
    pub statistical_summaries: Vec<StatisticalSummary>,
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

// --- Trend Analysis ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrendAnalysis {
    pub metric_name: String,
    pub data_points: Vec<TrendDataPoint>,
    pub trend_direction: AnalysisTrendDirection,
    pub slope: f64,
    pub r_squared: f64,
    pub forecast: Vec<ForecastPoint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrendDataPoint {
    pub timestamp: String,
    pub value: f64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum AnalysisTrendDirection {
    Increasing,
    Decreasing,
    Stable,
    Volatile,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForecastPoint {
    pub period: String,
    pub predicted_value: f64,
    pub confidence_lower: f64,
    pub confidence_upper: f64,
}

// --- Statistical Analysis ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatisticalSummary {
    pub metric_name: String,
    pub sample_size: usize,
    pub mean: f64,
    pub median: f64,
    pub std_deviation: f64,
    pub variance: f64,
    pub min: f64,
    pub max: f64,
    pub percentiles: HashMap<u8, f64>,
    pub outliers: Vec<f64>,
    pub distribution_type: DistributionType,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DistributionType {
    Normal,
    Skewed,
    Uniform,
    Bimodal,
    Unknown,
}

// --- Comparative Analysis ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComparativeResult {
    pub comparison_name: String,
    pub baseline_label: String,
    pub current_label: String,
    pub metrics: Vec<ComparisonMetric>,
    pub overall_change_percent: f64,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComparisonMetric {
    pub name: String,
    pub baseline_value: f64,
    pub current_value: f64,
    pub change_percent: f64,
    pub significant: bool,
}

// --- Predictive Analysis ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PredictiveModel {
    pub model_name: String,
    pub features: Vec<String>,
    pub coefficients: Vec<f64>,
    pub intercept: f64,
    pub r_squared: f64,
    pub training_samples: usize,
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
            trend_analyses: Vec::new(),
            comparative_results: Vec::new(),
            statistical_summaries: Vec::new(),
        }
    }

    pub fn calculate_risk_score(&self, factors: &[RiskFactor]) -> f64 {
        match self.risk_model.model_type {
            ModelType::WeightedScore => {
                let total_weight: f64 = factors.iter().map(|f| f.weight).sum();
                if total_weight == 0.0 {
                    return 0.0;
                }
                factors.iter()
                    .map(|f| f.weight * f.value)
                    .sum::<f64>()
                    / total_weight
            }
            ModelType::Bayesian => {
                let prior = 0.5;
                let likelihood: f64 = factors.iter()
                    .map(|f| f.value * f.weight)
                    .product();
                (prior * likelihood) / (prior * likelihood + (1.0 - prior) * (1.0 - likelihood))
            }
            ModelType::MachineLearning => {
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

    // --- Trend Analysis ---

    pub fn analyze_trend(&mut self, metric_name: &str, data_points: Vec<TrendDataPoint>) -> &TrendAnalysis {
        let n = data_points.len() as f64;
        if n < 2.0 {
            let analysis = TrendAnalysis {
                metric_name: metric_name.to_string(),
                data_points,
                trend_direction: AnalysisTrendDirection::Stable,
                slope: 0.0,
                r_squared: 0.0,
                forecast: Vec::new(),
            };
            self.trend_analyses.push(analysis);
            return self.trend_analyses.last().unwrap();
        }

        let values: Vec<f64> = data_points.iter().map(|p| p.value).collect();
        let mean_y = values.iter().sum::<f64>() / n;
        let mean_x = (n - 1.0) / 2.0;

        let mut ss_xy = 0.0;
        let mut ss_xx = 0.0;
        let mut ss_yy = 0.0;
        for (i, v) in values.iter().enumerate() {
            let x = i as f64;
            ss_xy += (x - mean_x) * (v - mean_y);
            ss_xx += (x - mean_x) * (x - mean_x);
            ss_yy += (v - mean_y) * (v - mean_y);
        }

        let slope = if ss_xx > 0.0 { ss_xy / ss_xx } else { 0.0 };
        let intercept = mean_y - slope * mean_x;

        let r_squared = if ss_yy > 0.0 {
            (ss_xy * ss_xy) / (ss_xx * ss_yy)
        } else {
            0.0
        };

        let trend_direction = if slope.abs() < 0.01 {
            AnalysisTrendDirection::Stable
        } else if slope > 0.0 {
            AnalysisTrendDirection::Increasing
        } else {
            AnalysisTrendDirection::Decreasing
        };

        let std_dev = (values.iter().map(|v| (v - mean_y).powi(2)).sum::<f64>() / n).sqrt();

        let mut forecast = Vec::new();
        for i in 0..3 {
            let future_x = n + i as f64;
            let predicted = slope * future_x + intercept;
            let confidence_range = std_dev * 1.96;
            forecast.push(ForecastPoint {
                period: format!("+{}", i + 1),
                predicted_value: predicted.max(0.0),
                confidence_lower: (predicted - confidence_range).max(0.0),
                confidence_upper: predicted + confidence_range,
            });
        }

        let analysis = TrendAnalysis {
            metric_name: metric_name.to_string(),
            data_points,
            trend_direction,
            slope,
            r_squared,
            forecast,
        };
        self.trend_analyses.push(analysis);
        self.trend_analyses.last().unwrap()
    }

    // --- Statistical Analysis ---

    pub fn compute_statistics(&mut self, metric_name: &str, values: Vec<f64>) -> &StatisticalSummary {
        let n = values.len();
        if n == 0 {
            let summary = StatisticalSummary {
                metric_name: metric_name.to_string(),
                sample_size: 0,
                mean: 0.0,
                median: 0.0,
                std_deviation: 0.0,
                variance: 0.0,
                min: 0.0,
                max: 0.0,
                percentiles: HashMap::new(),
                outliers: Vec::new(),
                distribution_type: DistributionType::Unknown,
            };
            self.statistical_summaries.push(summary);
            return self.statistical_summaries.last().unwrap();
        }

        let mut sorted = values.clone();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());

        let mean = sorted.iter().sum::<f64>() / n as f64;
        let median = if n % 2 == 0 {
            (sorted[n / 2 - 1] + sorted[n / 2]) / 2.0
        } else {
            sorted[n / 2]
        };
        let variance = sorted.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / n as f64;
        let std_dev = variance.sqrt();

        let mut percentiles = HashMap::new();
        for p in [10, 25, 50, 75, 90, 95, 99] {
            let idx = ((p as f64 / 100.0) * (n - 1) as f64).round() as usize;
            percentiles.insert(p, sorted[idx.min(n - 1)]);
        }

        let q1 = *percentiles.get(&25).unwrap();
        let q3 = *percentiles.get(&75).unwrap();
        let iqr = q3 - q1;
        let lower_bound = q1 - 1.5 * iqr;
        let upper_bound = q3 + 1.5 * iqr;
        let outliers: Vec<f64> = sorted.iter().filter(|&&v| v < lower_bound || v > upper_bound).copied().collect();

        let skewness = if std_dev > 0.0 {
            sorted.iter().map(|v| ((v - mean) / std_dev).powi(3)).sum::<f64>() / n as f64
        } else {
            0.0
        };

        let distribution_type = if skewness.abs() < 0.5 {
            DistributionType::Normal
        } else {
            DistributionType::Skewed
        };

        let summary = StatisticalSummary {
            metric_name: metric_name.to_string(),
            sample_size: n,
            mean,
            median,
            std_deviation: std_dev,
            variance,
            min: sorted[0],
            max: sorted[n - 1],
            percentiles,
            outliers,
            distribution_type,
        };
        self.statistical_summaries.push(summary);
        self.statistical_summaries.last().unwrap()
    }

    // --- Comparative Analysis ---

    pub fn compare_periods(
        &mut self,
        comparison_name: &str,
        baseline_label: &str,
        current_label: &str,
        baseline: &HashMap<String, f64>,
        current: &HashMap<String, f64>,
        significance_threshold: f64,
    ) -> &ComparativeResult {
        let mut metrics = Vec::new();
        let mut total_change = 0.0;
        let mut metric_count = 0;

        for (key, &base_val) in baseline {
            if let Some(&curr_val) = current.get(key) {
                let change = if base_val > 0.0 {
                    ((curr_val - base_val) / base_val) * 100.0
                } else if curr_val > 0.0 {
                    100.0
                } else {
                    0.0
                };

                metrics.push(ComparisonMetric {
                    name: key.clone(),
                    baseline_value: base_val,
                    current_value: curr_val,
                    change_percent: change,
                    significant: change.abs() >= significance_threshold,
                });

                total_change += change;
                metric_count += 1;
            }
        }

        let overall_change = if metric_count > 0 { total_change / metric_count as f64 } else { 0.0 };

        let recommendation = if overall_change < -10.0 {
            "Significant improvement detected. Continue current strategies.".to_string()
        } else if overall_change > 10.0 {
            "Security posture has degraded. Immediate review recommended.".to_string()
        } else {
            "Metrics are relatively stable. Monitor for changes.".to_string()
        };

        let result = ComparativeResult {
            comparison_name: comparison_name.to_string(),
            baseline_label: baseline_label.to_string(),
            current_label: current_label.to_string(),
            metrics,
            overall_change_percent: overall_change,
            recommendation,
        };
        self.comparative_results.push(result);
        self.comparative_results.last().unwrap()
    }

    // --- Predictive Analysis ---

    pub fn build_predictive_model(
        features: Vec<String>,
        feature_values: &[Vec<f64>],
        target_values: &[f64],
    ) -> PredictiveModel {
        let n = target_values.len() as f64;
        let k = features.len();

        if n < 2.0 || k == 0 {
            return PredictiveModel {
                model_name: "Linear Regression".to_string(),
                features,
                coefficients: vec![0.0; k],
                intercept: 0.0,
                r_squared: 0.0,
                training_samples: n as usize,
            };
        }

        let target_mean = target_values.iter().sum::<f64>() / n;
        let mut coefficients = Vec::new();

        for j in 0..k {
            let x_vals: Vec<f64> = feature_values.iter().map(|row| row[j]).collect();
            let x_mean = x_vals.iter().sum::<f64>() / n;

            let mut ss_xy = 0.0;
            let mut ss_xx = 0.0;
            for i in 0..target_values.len() {
                ss_xy += (x_vals[i] - x_mean) * (target_values[i] - target_mean);
                ss_xx += (x_vals[i] - x_mean) * (x_vals[i] - x_mean);
            }

            coefficients.push(if ss_xx > 0.0 { ss_xy / ss_xx } else { 0.0 });
        }

        let intercept = target_mean - coefficients.iter().enumerate().map(|(j, &c)| {
            let x_mean: f64 = feature_values.iter().map(|row| row[j]).sum::<f64>() / n;
            c * x_mean
        }).sum::<f64>();

        let ss_res: f64 = target_values.iter().enumerate().map(|(i, &actual)| {
            let predicted = intercept + coefficients.iter().enumerate().map(|(j, &c)| c * feature_values[i][j]).sum::<f64>();
            (actual - predicted).powi(2)
        }).sum();

        let ss_tot: f64 = target_values.iter().map(|&v| (v - target_mean).powi(2)).sum();

        let r_squared = if ss_tot > 0.0 { 1.0 - ss_res / ss_tot } else { 0.0 };

        PredictiveModel {
            model_name: "Linear Regression".to_string(),
            features,
            coefficients,
            intercept,
            r_squared,
            training_samples: n as usize,
        }
    }

    pub fn predict_with_model(model: &PredictiveModel, feature_values: &[f64]) -> f64 {
        model.intercept + model.coefficients.iter().zip(feature_values.iter()).map(|(c, x)| c * x).sum::<f64>()
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
        assert!(engine.trend_analyses.is_empty());
    }

    #[test]
    fn test_weighted_score_calculation() {
        let engine = AnalyticsEngine::new(ModelType::WeightedScore);
        let factors = vec![
            RiskFactor { name: "Severity".to_string(), weight: 0.5, value: 8.0, contribution: 0.0 },
            RiskFactor { name: "Exploitability".to_string(), weight: 0.3, value: 6.0, contribution: 0.0 },
            RiskFactor { name: "Impact".to_string(), weight: 0.2, value: 9.0, contribution: 0.0 },
        ];
        let score = engine.calculate_risk_score(&factors);
        assert!(score > 0.0 && score <= 10.0);
    }

    #[test]
    fn test_bayesian_calculation() {
        let engine = AnalyticsEngine::new(ModelType::Bayesian);
        let factors = vec![
            RiskFactor { name: "Factor1".to_string(), weight: 0.6, value: 0.8, contribution: 0.0 },
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
        engine.add_prediction(Prediction {
            target: "web-server".to_string(),
            probability: 0.75,
            confidence: 0.85,
            risk_factors: vec![],
        });
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
        let factor = RiskFactor { name: "Test".to_string(), weight: 0.5, value: 8.0, contribution: 4.0 };
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

    // --- Trend Analysis Tests ---

    #[test]
    fn test_trend_analysis_increasing() {
        let mut engine = AnalyticsEngine::new(ModelType::WeightedScore);
        let points: Vec<TrendDataPoint> = (0..10).map(|i| TrendDataPoint {
            timestamp: format!("2024-{:02}", i + 1),
            value: 5.0 + i as f64 * 0.5,
        }).collect();

        let analysis = engine.analyze_trend("risk_score", points);
        assert_eq!(analysis.trend_direction, AnalysisTrendDirection::Increasing);
        assert!(analysis.slope > 0.0);
        assert!(analysis.r_squared > 0.9);
        assert_eq!(analysis.forecast.len(), 3);
    }

    #[test]
    fn test_trend_analysis_decreasing() {
        let mut engine = AnalyticsEngine::new(ModelType::WeightedScore);
        let points: Vec<TrendDataPoint> = (0..10).map(|i| TrendDataPoint {
            timestamp: format!("2024-{:02}", i + 1),
            value: 10.0 - i as f64 * 0.5,
        }).collect();

        let analysis = engine.analyze_trend("vulns", points);
        assert_eq!(analysis.trend_direction, AnalysisTrendDirection::Decreasing);
        assert!(analysis.slope < 0.0);
    }

    #[test]
    fn test_trend_analysis_stable() {
        let mut engine = AnalyticsEngine::new(ModelType::WeightedScore);
        let points: Vec<TrendDataPoint> = (0..10).map(|i| TrendDataPoint {
            timestamp: format!("2024-{:02}", i + 1),
            value: 5.0 + (i as f64 * 0.001),
        }).collect();

        let analysis = engine.analyze_trend("metric", points);
        assert_eq!(analysis.trend_direction, AnalysisTrendDirection::Stable);
    }

    #[test]
    fn test_trend_insufficient_data() {
        let mut engine = AnalyticsEngine::new(ModelType::WeightedScore);
        let points = vec![TrendDataPoint { timestamp: "2024-01".to_string(), value: 5.0 }];
        let analysis = engine.analyze_trend("metric", points);
        assert_eq!(analysis.trend_direction, AnalysisTrendDirection::Stable);
        assert_eq!(analysis.forecast.len(), 0);
    }

    // --- Statistical Analysis Tests ---

    #[test]
    fn test_statistics_basic() {
        let mut engine = AnalyticsEngine::new(ModelType::WeightedScore);
        let values = vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0];
        let stats = engine.compute_statistics("test", values);

        assert_eq!(stats.sample_size, 10);
        assert!((stats.mean - 5.5).abs() < 0.01);
        assert!((stats.median - 5.5).abs() < 0.01);
        assert!(stats.std_deviation > 0.0);
        assert_eq!(stats.min, 1.0);
        assert_eq!(stats.max, 10.0);
        assert!(stats.outliers.is_empty());
    }

    #[test]
    fn test_statistics_with_outliers() {
        let mut engine = AnalyticsEngine::new(ModelType::WeightedScore);
        let mut values: Vec<f64> = (0..100).map(|i| i as f64).collect();
        values.push(1000.0); // outlier

        let stats = engine.compute_statistics("outlier_test", values);
        assert!(!stats.outliers.is_empty());
        assert!(stats.outliers.contains(&1000.0));
    }

    #[test]
    fn test_statistics_percentiles() {
        let mut engine = AnalyticsEngine::new(ModelType::WeightedScore);
        let values: Vec<f64> = (1..=100).map(|i| i as f64).collect();
        let stats = engine.compute_statistics("percentiles", values);

        assert!((stats.percentiles[&50] - 50.0).abs() < 2.0);
        assert!(stats.percentiles[&10] < stats.percentiles[&90]);
    }

    #[test]
    fn test_statistics_empty() {
        let mut engine = AnalyticsEngine::new(ModelType::WeightedScore);
        let stats = engine.compute_statistics("empty", vec![]);
        assert_eq!(stats.sample_size, 0);
        assert_eq!(stats.distribution_type, DistributionType::Unknown);
    }

    // --- Comparative Analysis Tests ---

    #[test]
    fn test_comparative_analysis_improvement() {
        let mut engine = AnalyticsEngine::new(ModelType::WeightedScore);
        let mut baseline = HashMap::new();
        baseline.insert("critical_vulns".to_string(), 10.0);
        baseline.insert("high_vulns".to_string(), 20.0);

        let mut current = HashMap::new();
        current.insert("critical_vulns".to_string(), 5.0);
        current.insert("high_vulns".to_string(), 12.0);

        let result = engine.compare_periods("Q1 vs Q2", "Q1", "Q2", &baseline, &current, 5.0);
        assert!(result.overall_change_percent < 0.0);
        assert!(result.recommendation.contains("improvement"));
    }

    #[test]
    fn test_comparative_analysis_degradation() {
        let mut engine = AnalyticsEngine::new(ModelType::WeightedScore);
        let mut baseline = HashMap::new();
        baseline.insert("risk_score".to_string(), 5.0);

        let mut current = HashMap::new();
        current.insert("risk_score".to_string(), 8.0);

        let result = engine.compare_periods("Before vs After", "Before", "After", &baseline, &current, 5.0);
        assert!(result.overall_change_percent > 0.0);
        assert!(result.recommendation.contains("degraded"));
    }

    #[test]
    fn test_comparative_significance() {
        let mut engine = AnalyticsEngine::new(ModelType::WeightedScore);
        let mut baseline = HashMap::new();
        baseline.insert("small_change".to_string(), 100.0);
        baseline.insert("big_change".to_string(), 100.0);

        let mut current = HashMap::new();
        current.insert("small_change".to_string(), 101.0);
        current.insert("big_change".to_string(), 150.0);

        let result = engine.compare_periods("Test", "Base", "Current", &baseline, &current, 10.0);
        let small = result.metrics.iter().find(|m| m.name == "small_change").unwrap();
        let big = result.metrics.iter().find(|m| m.name == "big_change").unwrap();
        assert!(!small.significant);
        assert!(big.significant);
    }

    // --- Predictive Model Tests ---

    #[test]
    fn test_predictive_model_simple() {
        let features = vec!["open_ports".to_string()];
        let feature_values = vec![
            vec![10.0], vec![20.0], vec![30.0], vec![40.0], vec![50.0],
        ];
        let target_values = vec![5.0, 7.0, 9.0, 11.0, 13.0];

        let model = AnalyticsEngine::build_predictive_model(features, &feature_values, &target_values);
        assert!(model.r_squared > 0.9);
        assert_eq!(model.coefficients.len(), 1);
        assert_eq!(model.training_samples, 5);
    }

    #[test]
    fn test_predict_with_model() {
        let features = vec!["x".to_string()];
        let feature_values = vec![vec![1.0], vec![2.0], vec![3.0], vec![4.0], vec![5.0]];
        let target_values = vec![2.0, 4.0, 6.0, 8.0, 10.0];

        let model = AnalyticsEngine::build_predictive_model(features, &feature_values, &target_values);
        let prediction = AnalyticsEngine::predict_with_model(&model, &[6.0]);
        assert!((prediction - 12.0).abs() < 1.0);
    }

    #[test]
    fn test_predictive_model_empty() {
        let model = AnalyticsEngine::build_predictive_model(vec!["x".to_string()], &[], &[]);
        assert_eq!(model.r_squared, 0.0);
        assert_eq!(model.training_samples, 0);
    }

    #[test]
    fn test_distribution_types() {
        assert_ne!(DistributionType::Normal, DistributionType::Skewed);
        assert_ne!(DistributionType::Uniform, DistributionType::Bimodal);
    }

    #[test]
    fn test_trend_directions() {
        assert_ne!(AnalysisTrendDirection::Increasing, AnalysisTrendDirection::Decreasing);
        assert_ne!(AnalysisTrendDirection::Stable, AnalysisTrendDirection::Volatile);
    }
}
