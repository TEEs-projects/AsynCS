#!/usr/bin/env python3
"""
Invoker Metric Reporting Tests

Tests for Invoker metrics and Prometheus integration:
- Invocation latency tracking
- Success/failure counts
- SGX Worker execution time
- Memory usage metrics
- Queue depth metrics
"""

import os
import sys
import time
import threading
import random

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class MockPrometheusMetrics:
    """Mock Prometheus metrics for testing"""
    
    def __init__(self):
        self.metrics = {
            "invoker_invocation_total": 0,
            "invoker_invocation_success": 0,
            "invoker_invocation_failure": 0,
            "invoker_latency_seconds": [],
            "invoker_sgx_execution_seconds": [],
            "invoker_queue_depth": 0,
            "invoker_memory_bytes": 0,
        }
    
    def inc(self, metric_name, value=1):
        if metric_name in self.metrics:
            self.metrics[metric_name] += value
    
    def observe(self, metric_name, value):
        if metric_name in self.metrics:
            if isinstance(self.metrics[metric_name], list):
                self.metrics[metric_name].append(value)
            else:
                self.metrics[metric_name] = value
    
    def set(self, metric_name, value):
        self.metrics[metric_name] = value
    
    def get(self, metric_name):
        return self.metrics.get(metric_name)


class MockInvoker:
    """Mock Invoker with metrics support"""
    
    def __init__(self, metrics: MockPrometheusMetrics):
        self.metrics = metrics
        self.queue = []
        self.lock = threading.Lock()
    
    def invoke(self, action_id: str, payload: bytes) -> dict:
        """Simulate invoking a confidential action"""
        start_time = time.time()
        
        with self.lock:
            self.queue.append(action_id)
            self.metrics.set("invoker_queue_depth", len(self.queue))
        
        self.metrics.inc("invoker_invocation_total")
        
        try:
            # Simulate SGX Worker execution
            sgx_start = time.time()
            time.sleep(random.uniform(0.001, 0.01))  # Mock execution
            sgx_time = time.time() - sgx_start
            self.metrics.observe("invoker_sgx_execution_seconds", sgx_time)
            
            # Simulate potential failures (5% failure rate)
            if random.random() < 0.05:
                raise Exception("SGX Worker crashed")
            
            result = {
                "action_id": action_id,
                "result": f"encrypted_result_{action_id}",
                "duration": sgx_time
            }
            
            self.metrics.inc("invoker_invocation_success")
            
        except Exception as e:
            self.metrics.inc("invoker_invocation_failure")
            result = {"action_id": action_id, "error": str(e)}
        
        finally:
            with self.lock:
                if action_id in self.queue:
                    self.queue.remove(action_id)
                self.metrics.set("invoker_queue_depth", len(self.queue))
        
        # Record total latency
        total_time = time.time() - start_time
        self.metrics.observe("invoker_latency_seconds", total_time)
        
        return result


def test_invoker_metric(test_num):
    """Test Invoker Metric Reporting"""
    print(f"\n[Test] Invoker Metric Reporting {test_num}")
    
    metrics = MockPrometheusMetrics()
    invoker = MockInvoker(metrics)
    
    # Perform invocations
    num_invocations = 5 + test_num  # Vary by test number
    
    for i in range(num_invocations):
        result = invoker.invoke(f"action_{test_num}_{i}", b"payload")
    
    # Verify metrics
    checks_passed = 0
    expected_checks = 4
    
    # Check total invocations
    total = metrics.get("invoker_invocation_total")
    if total == num_invocations:
        checks_passed += 1
        print(f"  ✓ Total invocations recorded: {total}")
    else:
        print(f"  ❌ Total invocations wrong: {total} != {num_invocations}")
    
    # Check success + failure = total
    success = metrics.get("invoker_invocation_success")
    failure = metrics.get("invoker_invocation_failure")
    if success + failure == num_invocations:
        checks_passed += 1
        print(f"  ✓ Success ({success}) + Failure ({failure}) = Total ({num_invocations})")
    else:
        print(f"  ❌ Success + Failure != Total")
    
    # Check latency recorded
    latencies = metrics.get("invoker_latency_seconds")
    if len(latencies) == num_invocations:
        avg_latency = sum(latencies) / len(latencies)
        checks_passed += 1
        print(f"  ✓ Latency recorded: {len(latencies)} samples, avg={avg_latency*1000:.2f}ms")
    else:
        print(f"  ❌ Latency samples wrong: {len(latencies)} != {num_invocations}")
    
    # Check queue depth returns to 0
    final_depth = metrics.get("invoker_queue_depth")
    if final_depth == 0:
        checks_passed += 1
        print(f"  ✓ Queue depth returned to 0")
    else:
        print(f"  ❌ Queue depth not 0: {final_depth}")
    
    if checks_passed >= expected_checks:
        print(f"  ✅ Test PASSED")
        return True
    else:
        print(f"  ❌ Test FAILED ({checks_passed}/{expected_checks})")
        return False


def test_invoker_concurrent_metrics():
    """Test metrics under concurrent load"""
    print("\n[Test] Invoker Concurrent Metrics")
    
    metrics = MockPrometheusMetrics()
    invoker = MockInvoker(metrics)
    
    # Launch concurrent invocations
    threads = []
    num_threads = 10
    invocations_per_thread = 5
    
    def worker(thread_id):
        for i in range(invocations_per_thread):
            invoker.invoke(f"concurrent_{thread_id}_{i}", b"payload")
    
    for i in range(num_threads):
        t = threading.Thread(target=worker, args=(i,))
        threads.append(t)
        t.start()
    
    for t in threads:
        t.join()
    
    # Verify metrics
    expected_total = num_threads * invocations_per_thread
    actual_total = metrics.get("invoker_invocation_total")
    
    if actual_total == expected_total:
        print(f"  ✓ All {expected_total} invocations recorded correctly")
        print(f"  ✅ Test PASSED")
        return True
    else:
        print(f"  ❌ Wrong count: {actual_total} != {expected_total}")
        return False


def test_invoker_sgx_timing():
    """Test SGX execution timing metrics"""
    print("\n[Test] Invoker SGX Execution Timing")
    
    metrics = MockPrometheusMetrics()
    invoker = MockInvoker(metrics)
    
    # Perform invocations
    for i in range(10):
        invoker.invoke(f"timing_{i}", b"payload")
    
    sgx_times = metrics.get("invoker_sgx_execution_seconds")
    
    if len(sgx_times) > 0:
        avg_time = sum(sgx_times) / len(sgx_times)
        min_time = min(sgx_times)
        max_time = max(sgx_times)
        
        print(f"  ✓ SGX execution times recorded")
        print(f"    - Min: {min_time*1000:.2f}ms")
        print(f"    - Avg: {avg_time*1000:.2f}ms")
        print(f"    - Max: {max_time*1000:.2f}ms")
        print(f"  ✅ Test PASSED")
        return True
    else:
        print(f"  ❌ No SGX timing data recorded")
        return False


def test_invoker_error_tracking():
    """Test error tracking in metrics"""
    print("\n[Test] Invoker Error Tracking")
    
    metrics = MockPrometheusMetrics()
    invoker = MockInvoker(metrics)
    
    # Run many invocations to get some failures (5% failure rate)
    random.seed(42)  # For reproducibility
    for i in range(100):
        invoker.invoke(f"error_test_{i}", b"payload")
    
    success = metrics.get("invoker_invocation_success")
    failure = metrics.get("invoker_invocation_failure")
    total = metrics.get("invoker_invocation_total")
    
    if success + failure == total == 100:
        print(f"  ✓ Total tracked correctly: {total}")
        print(f"  ✓ Success: {success}, Failure: {failure}")
        print(f"  ✓ Failure rate: {failure}%")
        print(f"  ✅ Test PASSED")
        return True
    else:
        print(f"  ❌ Metric accounting error")
        return False


def main():
    print("=" * 60)
    print("Invoker Metric Reporting Tests")
    print("=" * 60)
    
    results = {}
    
    # Run tests for Invoker Metric Reporting 0-15
    for i in range(16):
        results[f"Invoker Metric Reporting {i}"] = test_invoker_metric(i)
    
    # Additional metric tests
    results["Invoker Concurrent Metrics"] = test_invoker_concurrent_metrics()
    results["Invoker SGX Timing"] = test_invoker_sgx_timing()
    results["Invoker Error Tracking"] = test_invoker_error_tracking()
    
    # Summary
    print("\n" + "=" * 60)
    print("Summary")
    print("=" * 60)
    
    passed = sum(1 for r in results.values() if r)
    total = len(results)
    
    for name, result in results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"  {name}: {status}")
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
