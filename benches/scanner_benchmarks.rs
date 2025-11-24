// Performance Benchmarks for Nemue Scanner
// Run with: cargo bench

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use nemue::scanner::{PortParser, TargetParser, TimingTemplate};
use nemue::script::ScriptArgs;
use std::net::IpAddr;

// Port Parsing Benchmarks
fn benchmark_port_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("port_parsing");
    
    group.bench_function("single_port", |b| {
        b.iter(|| PortParser::parse(black_box("80")))
    });
    
    group.bench_function("port_range_small", |b| {
        b.iter(|| PortParser::parse(black_box("1-100")))
    });
    
    group.bench_function("port_range_large", |b| {
        b.iter(|| PortParser::parse(black_box("1-65535")))
    });
    
    group.bench_function("mixed_ports", |b| {
        b.iter(|| PortParser::parse(black_box("22,80,443,8000-8100")))
    });
    
    group.bench_function("common_preset", |b| {
        b.iter(|| PortParser::parse(black_box("common")))
    });
    
    group.bench_function("top1000_preset", |b| {
        b.iter(|| PortParser::parse(black_box("top1000")))
    });
    
    group.finish();
}

// Target Parsing Benchmarks
fn benchmark_target_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("target_parsing");
    
    group.bench_function("single_ip", |b| {
        b.iter(|| TargetParser::parse(black_box("192.168.1.1")))
    });
    
    group.bench_function("cidr_24", |b| {
        b.iter(|| TargetParser::parse(black_box("192.168.1.0/24")))
    });
    
    group.bench_function("cidr_16", |b| {
        b.iter(|| TargetParser::parse(black_box("192.168.0.0/16")))
    });
    
    group.bench_function("ipv6_single", |b| {
        b.iter(|| TargetParser::parse(black_box("fe80::1")))
    });
    
    group.finish();
}

// Timing Configuration Benchmarks
fn benchmark_timing(c: &mut Criterion) {
    let mut group = c.benchmark_group("timing");
    
    group.bench_function("template_creation", |b| {
        b.iter(|| {
            for i in 0..=5 {
                let _ = TimingTemplate::from_number(black_box(i));
            }
        })
    });
    
    group.bench_function("template_to_config", |b| {
        let template = TimingTemplate::Aggressive;
        b.iter(|| black_box(&template).to_config())
    });
    
    group.bench_function("config_validation", |b| {
        b.iter(|| {
            let mut config = TimingTemplate::Normal.to_config();
            config.validate();
        })
    });
    
    group.finish();
}

// Script Arguments Parsing Benchmarks
fn benchmark_script_args(c: &mut Criterion) {
    let mut group = c.benchmark_group("script_args");
    
    group.bench_function("parse_simple", |b| {
        b.iter(|| ScriptArgs::parse(black_box("user=admin,pass=test")))
    });
    
    group.bench_function("parse_complex", |b| {
        b.iter(|| ScriptArgs::parse(black_box(
            "user=admin,pass=test123,timeout=30,url=http://example.com,debug=true"
        )))
    });
    
    group.bench_function("parse_quoted", |b| {
        b.iter(|| ScriptArgs::parse(black_box(
            r#"msg="hello world",url='http://example.com',data="key=value""#
        )))
    });
    
    group.bench_function("to_lua_table", |b| {
        let args = ScriptArgs::parse("user=admin,pass=test,timeout=30").unwrap();
        b.iter(|| black_box(&args).to_lua_table())
    });
    
    group.finish();
}

// String Operations Benchmarks
fn benchmark_string_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("string_ops");
    
    group.bench_function("ip_addr_parsing", |b| {
        b.iter(|| {
            let _: IpAddr = black_box("192.168.1.1").parse().unwrap();
        })
    });
    
    group.bench_function("ipv6_parsing", |b| {
        b.iter(|| {
            let _: IpAddr = black_box("fe80::1").parse().unwrap();
        })
    });
    
    group.finish();
}

// Memory Allocation Benchmarks
fn benchmark_allocations(c: &mut Criterion) {
    let mut group = c.benchmark_group("allocations");
    
    group.bench_function("vec_small", |b| {
        b.iter(|| {
            let _v: Vec<u16> = (1..=100).collect();
        })
    });
    
    group.bench_function("vec_large", |b| {
        b.iter(|| {
            let _v: Vec<u16> = (1..=10000).collect();
        })
    });
    
    group.bench_function("hashmap_insert", |b| {
        b.iter(|| {
            let mut map = std::collections::HashMap::new();
            for i in 0..100 {
                map.insert(format!("key{}", i), format!("value{}", i));
            }
        })
    });
    
    group.finish();
}

// Comparison: Different Port Range Sizes
fn benchmark_port_range_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("port_range_scaling");
    
    for size in [10, 100, 1000, 10000].iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            size,
            |b, &size| {
                let range = format!("1-{}", size);
                b.iter(|| PortParser::parse(black_box(&range)))
            }
        );
    }
    
    group.finish();
}

// Comparison: Different CIDR Sizes
fn benchmark_cidr_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("cidr_scaling");
    
    let cidrs = vec![
        ("cidr_30", "192.168.1.0/30"),   // 4 hosts
        ("cidr_28", "192.168.1.0/28"),   // 16 hosts
        ("cidr_24", "192.168.1.0/24"),   // 256 hosts
        ("cidr_22", "192.168.0.0/22"),   // 1024 hosts
    ];
    
    for (name, cidr) in cidrs {
        group.bench_function(name, |b| {
            b.iter(|| TargetParser::parse(black_box(cidr)))
        });
    }
    
    group.finish();
}

criterion_group!(
    benches,
    benchmark_port_parsing,
    benchmark_target_parsing,
    benchmark_timing,
    benchmark_script_args,
    benchmark_string_operations,
    benchmark_allocations,
    benchmark_port_range_scaling,
    benchmark_cidr_scaling
);

criterion_main!(benches);
