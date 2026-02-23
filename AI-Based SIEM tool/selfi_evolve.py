# self_evolve.py
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import time
import os
import subprocess
import json
import random
import sys
import io

# Fix Unicode encoding for Windows
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')


class SelfEvolvingSIEM:
    """
    A self-evolving SIEM system that continuously learns and improves
    """

    def __init__(self):
        self.log_file = 'logs/evolution_log.json'
        self.data_dir = 'data'
        self.models_dir = 'models'
        self.rules_dir = 'rules'

        # Get the path to the current Python executable (from virtual environment)
        self.python_executable = sys.executable


        # Create directories if they don't exist
        os.makedirs('logs', exist_ok=True)
        os.makedirs(self.data_dir, exist_ok=True)
        os.makedirs(self.models_dir, exist_ok=True)
        os.makedirs(self.rules_dir, exist_ok=True)

        self.load_history()

    def load_history(self):
        """Load evolution history"""
        if os.path.exists(self.log_file):
            try:
                with open(self.log_file, 'r') as f:
                    self.history = json.load(f)
            except:
                self.history = {
                    'iterations': [],
                    'rules_generated': [],
                    'performance_metrics': [],
                    'model_versions': []
                }
        else:
            self.history = {
                'iterations': [],
                'rules_generated': [],
                'performance_metrics': [],
                'model_versions': []
            }

    def save_history(self):
        """Save evolution history"""
        try:
            with open(self.log_file, 'w') as f:
                json.dump(self.history, f, indent=2)
        except Exception as e:
            print(f"⚠ Error saving history: {e}")

    def ingest_new_data(self):
        """Simulate ingesting new log data"""
        print("\n[1] Ingesting new data...")

        # Check if original dataset exists
        original_data = os.path.join(self.data_dir, 'rba-dataset.csv')
        if not os.path.exists(original_data):
            print("Original dataset not found!")
            print(f"   Looked for: {original_data}")
            return None

        # Create a new sample with slight variations
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        new_data_file = os.path.join(self.data_dir, f'new_logs_{timestamp}.csv')

        try:
            # Load original data and take a sample
            print(f"  Reading original dataset...")
            df = pd.read_csv(original_data, nrows=10000)

            # Add some drift to simulate evolving patterns
            print("  Adding concept drift to simulate new attack patterns...")

            # Modify timestamps if they exist
            if 'Login Timestamp' in df.columns:
                df['Login Timestamp'] = pd.to_datetime(df['Login Timestamp'])
                # Shift some timestamps
                indices = random.sample(range(len(df)), min(5000, len(df) // 10))
                for idx in indices:
                    df.loc[idx, 'Login Timestamp'] = df.loc[idx, 'Login Timestamp'] + timedelta(
                        hours=random.randint(1, 48))

            # Flip some attack labels
            if 'Is Attack IP' in df.columns:
                flip_idx = random.sample(range(len(df)), min(1000, len(df) // 20))
                df.loc[flip_idx, 'Is Attack IP'] = 1 - df.loc[flip_idx, 'Is Attack IP']

            if 'Is Account Takeover' in df.columns:
                flip_idx = random.sample(range(len(df)), min(500, len(df) // 40))
                df.loc[flip_idx, 'Is Account Takeover'] = 1 - df.loc[flip_idx, 'Is Account Takeover']

            # Save new data
            df.to_csv(new_data_file, index=False)
            print(f"✓ Created new dataset: {os.path.basename(new_data_file)}")
            print(f"  Rows: {len(df):,}")

            return new_data_file

        except Exception as e:
            print(f"Error creating new data: {e}")
            return None

    def retrain_models(self, data_file):
        """Retrain models on new data"""
        print("\n[2] Retraining models on new data...")

        # Backup current models
        backup_dir = os.path.join('models_backup', datetime.now().strftime("%Y%m%d_%H%M%S"))
        backed_up = False

        if os.path.exists(self.models_dir):
            for f in os.listdir(self.models_dir):
                if f.endswith(('.pkl', '.keras')):
                    try:
                        os.makedirs(backup_dir, exist_ok=True)
                        src = os.path.join(self.models_dir, f)
                        dst = os.path.join(backup_dir, f)
                        import shutil
                        shutil.copy2(src, dst)
                        backed_up = True
                    except:
                        pass

        if backed_up:
            print(f"  ✓ Backed up existing models to {backup_dir}")

        try:
            # Run anomaly detector
            print(f"  Running anomaly_detector.py...")

            env = os.environ.copy()
            env['TF_CPP_MIN_LOG_LEVEL'] = '2'
            env['PYTHONIOENCODING'] = 'utf-8'

            result = subprocess.run(
                [self.python_executable, 'anomaly_detector.py'],
                capture_output=True,
                text=True,
                timeout=3600,
                env=env,
                encoding='utf-8',
                errors='replace'
            )

            if result.returncode == 0:
                print("✓ Models retrained successfully")

                self.history['iterations'].append({
                    'timestamp': datetime.now().isoformat(),
                    'data_file': os.path.basename(data_file),
                    'success': True
                })

                self.history['model_versions'].append({
                    'timestamp': datetime.now().isoformat(),
                    'version': len(self.history['model_versions']) + 1
                })

                return True
            else:
                print("✗ Retraining failed")
                print(f"  Error: {result.stderr[:200]}")

                # Restore from backup
                if backed_up:
                    print("  Restoring models from backup...")
                    for f in os.listdir(backup_dir):
                        src = os.path.join(backup_dir, f)
                        dst = os.path.join(self.models_dir, f)
                        import shutil
                        shutil.copy2(src, dst)
                    print("  ✓ Models restored")
                return False

        except subprocess.TimeoutExpired:
            print("✗ Retraining timed out")
            return False
        except Exception as e:
            print(f"✗ Unexpected error: {e}")
            return False

    def generate_new_rules(self):
        """Generate new rules based on latest anomalies"""
        print("\n[3] Generating new detection rules...")

        try:
            # Check if detection results exist
            if not os.path.exists('data/result/detection_results.csv'):
                print("  ⚠ No detection results found. Skipping rule generation.")
                return 0

            # Run rule generator
            print(f"  Running rule_generator.py...")

            result = subprocess.run(
                [self.python_executable, 'rule_generator.py'],
                capture_output=True,
                text=True,
                timeout=1800,
                encoding='utf-8',
                errors='replace'
            )

            if result.returncode == 0:
                # Count new rules
                rule_count = len([f for f in os.listdir(self.rules_dir) if f.endswith('.yml')])
                self.history['rules_generated'].append({
                    'timestamp': datetime.now().isoformat(),
                    'count': rule_count
                })
                print(f"✓ Generated {rule_count} rules")

                # List the rules
                for f in os.listdir(self.rules_dir):
                    if f.endswith('.yml'):
                        print(f"    - {f}")

                return rule_count
            else:
                print("✗ Rule generation failed")
                print(f"  Error: {result.stderr[:200]}")
                return 0

        except Exception as e:
            print(f"✗ Error generating rules: {e}")
            return 0

    def evaluate_performance(self):
        """Evaluate how well rules are performing"""
        print("\n[4] Evaluating detection performance...")

        results_file = os.path.join(self.data_dir, 'detection_results.csv')
        if not os.path.exists(results_file):
            print("  ⚠ No detection results found")
            return None

        try:
            df = pd.read_csv(results_file)

            # Find anomaly column
            anomaly_col = None
            for col in ['ae_anomaly', 'iso_anomaly']:
                if col in df.columns:
                    anomaly_col = col
                    break

            # Find attack column
            attack_col = None
            for col in ['Is Attack IP', 'Is Account Takeover', 'true_attack']:
                if col in df.columns:
                    attack_col = col
                    break

            if anomaly_col and attack_col:
                # Calculate metrics
                true_pos = ((df[anomaly_col] == True) & (df[attack_col] == True)).sum()
                false_pos = ((df[anomaly_col] == True) & (df[attack_col] == False)).sum()
                false_neg = ((df[anomaly_col] == False) & (df[attack_col] == True)).sum()
                true_neg = ((df[anomaly_col] == False) & (df[attack_col] == False)).sum()

                total_attacks = true_pos + false_neg
                total_normal = false_pos + true_neg

                # Calculate rates
                detection_rate = (true_pos / total_attacks * 100) if total_attacks > 0 else 0
                false_positive_rate = (false_pos / total_normal * 100) if total_normal > 0 else 0

                # Precision and recall
                precision = true_pos / (true_pos + false_pos) if (true_pos + false_pos) > 0 else 0
                recall = true_pos / (true_pos + false_neg) if (true_pos + false_neg) > 0 else 0
                f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

                metrics = {
                    'timestamp': datetime.now().isoformat(),
                    'detection_rate': float(detection_rate),
                    'false_positive_rate': float(false_positive_rate),
                    'precision': float(precision),
                    'recall': float(recall),
                    'f1_score': float(f1),
                    'true_positives': int(true_pos),
                    'false_positives': int(false_pos),
                    'false_negatives': int(false_neg),
                    'true_negatives': int(true_neg),
                    'total_attacks': int(total_attacks)
                }

                self.history['performance_metrics'].append(metrics)

                print(f"  Detection rate: {detection_rate:.1f}% ({true_pos}/{total_attacks})")
                print(f"  False positive rate: {false_positive_rate:.1f}%")
                print(f"  Precision: {precision:.3f}")
                print(f"  Recall: {recall:.3f}")
                print(f"  F1 Score: {f1:.3f}")

                return metrics
            else:
                print("  ⚠ Required columns not found")
                print(f"    Anomaly col: {anomaly_col}")
                print(f"    Attack col: {attack_col}")

        except Exception as e:
            print(f"  ⚠ Error evaluating performance: {e}")

        return None

    def generate_report(self):
        """Generate a report of the evolution"""
        print("\n[5] Generating evolution report...")

        report = {
            'generated_at': datetime.now().isoformat(),
            'total_iterations': len(self.history['iterations']),
            'total_rules_generated': sum(r.get('count', 0) for r in self.history['rules_generated']),
            'current_rules': len([f for f in os.listdir(self.rules_dir) if f.endswith('.yml')]),
            'performance_summary': {}
        }

        # Calculate performance trend
        if len(self.history['performance_metrics']) >= 2:
            first = self.history['performance_metrics'][0]
            last = self.history['performance_metrics'][-1]

            report['performance_improvement'] = {
                'detection_rate_change': round(last['detection_rate'] - first['detection_rate'], 2),
                'f1_score_change': round(last['f1_score'] - first['f1_score'], 3),
                'false_positive_change': round(last['false_positive_rate'] - first['false_positive_rate'], 2)
            }

        # Latest performance
        if self.history['performance_metrics']:
            latest = self.history['performance_metrics'][-1]
            report['latest_performance'] = {
                'detection_rate': latest['detection_rate'],
                'f1_score': latest['f1_score'],
                'false_positive_rate': latest['false_positive_rate']
            }

        # Save report
        report_file = os.path.join('logs', f'evolution_report_{datetime.now().strftime("%Y%m%d")}.json')
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)

        print(f"✓ Report saved to {report_file}")

        # Print summary
        print("\nEvolution Summary:")
        print(f"  Iterations completed: {report['total_iterations']}")
        print(f"  Total rules generated: {report['total_rules_generated']}")
        print(f"  Current active rules: {report['current_rules']}")

        if 'latest_performance' in report:
            print(f"\n  Latest Performance:")
            print(f"    Detection rate: {report['latest_performance']['detection_rate']:.1f}%")
            print(f"    F1 Score: {report['latest_performance']['f1_score']:.3f}")

        if 'performance_improvement' in report:
            print(f"\n  Improvement:")
            imp = report['performance_improvement']
            print(f"    Detection rate: {imp['detection_rate_change']:+.1f}%")
            print(f"    F1 Score: {imp['f1_score_change']:+.3f}")

        return report

    def evolution_cycle(self):
        """Run one complete evolution cycle"""
        cycle_num = len(self.history['iterations']) + 1

        print("\n" + "=" * 60)
        print(f"EVOLUTION CYCLE #{cycle_num}")
        print(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 60)

        # Step 1: Ingest new data
        new_data = self.ingest_new_data()
        if not new_data:
            print("No new data available - stopping cycle")
            return False

        # Step 2: Retrain models
        if not self.retrain_models(new_data):
            print("Model retraining failed - stopping cycle")
            return False

        # Step 3: Generate new rules
        self.generate_new_rules()

        # Step 4: Evaluate performance
        self.evaluate_performance()

        # Step 5: Generate report
        self.generate_report()

        # Save history
        self.save_history()

        print("\n" + "=" * 60)
        print("EVOLUTION CYCLE COMPLETE")
        print("=" * 60)

        return True

    def run_continuously(self, interval_hours=24):
        """Run evolution cycles continuously"""
        print(f"\nStarting continuous evolution (every {interval_hours} hours)")
        print("Press Ctrl+C to stop gracefully")
        print("-" * 50)

        cycle_count = 0

        try:
            while True:
                cycle_count += 1
                print(f"\nCycle #{cycle_count} starting...")

                success = self.evolution_cycle()

                if success:
                    next_time = datetime.now() + timedelta(hours=interval_hours)
                    print(f"\nNext cycle at {next_time.strftime('%Y-%m-%d %H:%M:%S')}")

                # Wait for next cycle
                for i in range(interval_hours * 60):  # Check every minute
                    time.sleep(60)

        except KeyboardInterrupt:
            print("\n\nEvolution stopped by user")
            print(f"Total cycles completed: {cycle_count}")
            self.generate_report()

    def show_history(self):
        """Display evolution history"""
        print("\nEVOLUTION HISTORY")
        print("=" * 50)

        print(f"\nTotal iterations: {len(self.history['iterations'])}")
        print(f"Total rules generated: {sum(r.get('count', 0) for r in self.history['rules_generated'])}")

        if self.history['performance_metrics']:
            print("\nPerformance Over Time:")
            for i, metrics in enumerate(self.history['performance_metrics'][-5:], 1):
                print(f"\n  Cycle {i}:")
                print(f"    Detection rate: {metrics['detection_rate']:.1f}%")
                print(f"    F1 Score: {metrics['f1_score']:.3f}")
                print(f"    False positives: {metrics['false_positive_rate']:.1f}%")

        # Show current rules
        if os.path.exists(self.rules_dir):
            rules = [f for f in os.listdir(self.rules_dir) if f.endswith('.yml')]
            if rules:
                print(f"\nCurrent rules ({len(rules)}):")
                for rule in sorted(rules)[-10:]:
                    print(f"  - {rule}")


# Main execution
if __name__ == "__main__":
    siem = SelfEvolvingSIEM()

    print("\nSELF-EVOLVING SIEM SYSTEM")
    print("=" * 25)
    print("\nWhat would you like to do?")
    print("1. Run one evolution cycle")
    print("2. Run continuously (every 24 hours)")
    print("3. Show evolution history")
    print("4. Generate performance report")
    print("5. Exit")

    while True:
        choice = input("\n Enter choice (1-5): ").strip()

        if choice == '1':
            siem.evolution_cycle()


        elif choice == '2':
            try:
                hours = input("Enter interval in hours (default 24): ").strip()
                interval = int(hours) if hours else 24
                siem.run_continuously(interval_hours=interval)
            except ValueError:
                print(" Invalid input, using default 24 hours")
                siem.run_continuously()


        elif choice == '3':
            siem.show_history()


        elif choice == '4':
            siem.generate_report()


        elif choice == '5':
            print(" Goodbye!")
            break


        else:
            print(" Invalid choice. Please enter 1-5")
