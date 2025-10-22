#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Анализатор логов
Парсит и анализирует лог-файлы различных форматов
"""

import re
from datetime import datetime
from collections import Counter, defaultdict
import json

class LogAnalyzer:
    def __init__(self):
        self.log_patterns = {
            'apache': r'(\S+) \S+ \S+ \[(.*?)\] "(.*?)" (\d+) (\d+)',
            'nginx': r'(\S+) - - \[(.*?)\] "(.*?)" (\d+) (\d+) "(.*?)" "(.*?)"',
            'common': r'(\S+) - - \[(.*?)\] "(.*?)" (\d+) (\d+)',
            'combined': r'(\S+) - - \[(.*?)\] "(.*?)" (\d+) (\d+) "(.*?)" "(.*?)"',
            'custom': r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (\w+): (.+)'
        }
        
        self.status_codes = {
            200: 'OK', 404: 'Not Found', 500: 'Server Error',
            301: 'Moved', 302: 'Redirect', 403: 'Forbidden'
        }
    
    def parse_log_file(self, filename, log_format='auto'):
        """Парсит лог-файл"""
        entries = []
        
        try:
            with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    entry = self.parse_log_line(line, log_format)
                    if entry:
                        entry['line_number'] = line_num
                        entries.append(entry)
            
            return entries
            
        except FileNotFoundError:
            print(f"❌ Файл не найден: {filename}")
            return []
        except Exception as e:
            print(f"❌ Ошибка чтения файла: {e}")
            return []
    
    def parse_log_line(self, line, log_format='auto'):
        """Парсит одну строку лога"""
        if log_format == 'auto':
            # Автоопределение формата
            for format_name, pattern in self.log_patterns.items():
                match = re.match(pattern, line)
                if match:
                    return self.extract_fields(match, format_name, line)
        else:
            pattern = self.log_patterns.get(log_format)
            if pattern:
                match = re.match(pattern, line)
                if match:
                    return self.extract_fields(match, log_format, line)
        
        return {'raw_line': line, 'parsed': False}
    
    def extract_fields(self, match, format_name, raw_line):
        """Извлекает поля из совпадения"""
        groups = match.groups()
        entry = {'raw_line': raw_line, 'parsed': True, 'format': format_name}
        
        if format_name in ['apache', 'nginx', 'common', 'combined']:
            entry.update({
                'ip': groups[0],
                'timestamp': self.parse_timestamp(groups[1]),
                'request': groups[2],
                'status': int(groups[3]) if groups[3].isdigit() else 0,
                'size': int(groups[4]) if groups[4].isdigit() else 0
            })
            
            # Парсим HTTP запрос
            request_parts = groups[2].split()
            if len(request_parts) >= 2:
                entry['method'] = request_parts[0]
                entry['path'] = request_parts[1]
                entry['protocol'] = request_parts[2] if len(request_parts) > 2 else 'HTTP/1.1'
            
            # Дополнительные поля для nginx/combined
            if format_name in ['nginx', 'combined'] and len(groups) > 5:
                entry['referer'] = groups[5] if groups[5] != '-' else None
                entry['user_agent'] = groups[6] if len(groups) > 6 else None
        
        elif format_name == 'custom':
            entry.update({
                'timestamp': self.parse_timestamp(groups[0]),
                'level': groups[1],
                'message': groups[2]
            })
        
        return entry
    
    def parse_timestamp(self, timestamp_str):
        """Парсит временную метку"""
        timestamp_formats = [
            '%d/%b/%Y:%H:%M:%S %z',  # Apache format
            '%d/%b/%Y:%H:%M:%S',     # Apache without timezone
            '%Y-%m-%d %H:%M:%S',     # Custom format
            '%Y-%m-%d %H:%M:%S.%f'   # With microseconds
        ]
        
        for fmt in timestamp_formats:
            try:
                return datetime.strptime(timestamp_str, fmt)
            except ValueError:
                continue
        
        return None
    
    def analyze_entries(self, entries):
        """Анализирует записи логов"""
        if not entries:
            return {}
        
        parsed_entries = [e for e in entries if e.get('parsed', False)]
        
        analysis = {
            'total_entries': len(entries),
            'parsed_entries': len(parsed_entries),
            'parse_rate': len(parsed_entries) / len(entries) * 100 if entries else 0
        }
        
        if parsed_entries:
            # Анализ IP адресов
            ips = [e['ip'] for e in parsed_entries if 'ip' in e]
            analysis['top_ips'] = dict(Counter(ips).most_common(10))
            analysis['unique_ips'] = len(set(ips))
            
            # Анализ статус кодов
            status_codes = [e['status'] for e in parsed_entries if 'status' in e and e['status']]
            analysis['status_codes'] = dict(Counter(status_codes).most_common())
            
            # Анализ HTTP методов
            methods = [e['method'] for e in parsed_entries if 'method' in e]
            analysis['http_methods'] = dict(Counter(methods).most_common())
            
            # Анализ путей
            paths = [e['path'] for e in parsed_entries if 'path' in e]
            analysis['top_paths'] = dict(Counter(paths).most_common(10))
            
            # Анализ размеров ответов
            sizes = [e['size'] for e in parsed_entries if 'size' in e and e['size']]
            if sizes:
                analysis['response_sizes'] = {
                    'total_bytes': sum(sizes),
                    'avg_size': sum(sizes) / len(sizes),
                    'max_size': max(sizes),
                    'min_size': min(sizes)
                }
            
            # Анализ времени
            timestamps = [e['timestamp'] for e in parsed_entries if 'timestamp' in e and e['timestamp']]
            if timestamps:
                analysis['time_range'] = {
                    'start': min(timestamps),
                    'end': max(timestamps),
                    'duration': str(max(timestamps) - min(timestamps))
                }
                
                # Анализ по часам
                hours = [t.hour for t in timestamps]
                analysis['traffic_by_hour'] = dict(Counter(hours).most_common())
        
        return analysis
    
    def detect_anomalies(self, entries):
        """Обнаруживает аномалии в логах"""
        anomalies = []
        
        for entry in entries:
            if not entry.get('parsed', False):
                continue
            
            # 4xx и 5xx ошибки
            if entry.get('status', 0) >= 400:
                anomalies.append({
                    'type': 'error_status',
                    'severity': 'high' if entry['status'] >= 500 else 'medium',
                    'message': f"HTTP {entry['status']} from {entry.get('ip', 'unknown')}",
                    'entry': entry
                })
            
            # Большие размеры ответов (>10MB)
            if entry.get('size', 0) > 10 * 1024 * 1024:
                anomalies.append({
                    'type': 'large_response',
                    'severity': 'medium',
                    'message': f"Large response {entry['size']} bytes",
                    'entry': entry
                })
            
            # Подозрительные пути
            suspicious_patterns = [
                r'\.php$', r'admin', r'wp-admin', r'\.env',
                r'backup', r'config', r'\.git'
            ]
            
            path = entry.get('path', '')
            for pattern in suspicious_patterns:
                if re.search(pattern, path, re.IGNORECASE):
                    anomalies.append({
                        'type': 'suspicious_path',
                        'severity': 'high',
                        'message': f"Suspicious path access: {path}",
                        'entry': entry
                    })
                    break
        
        return anomalies
    
    def generate_report(self, analysis, anomalies):
        """Генерирует отчет анализа"""
        report = []
        report.append("📊 ОТЧЕТ АНАЛИЗА ЛОГОВ")
        report.append("=" * 50)
        
        # Общая статистика
        report.append(f"\n📈 ОБЩАЯ СТАТИСТИКА")
        report.append(f"Всего записей: {analysis.get('total_entries', 0)}")
        report.append(f"Распознано: {analysis.get('parsed_entries', 0)}")
        report.append(f"Процент распознавания: {analysis.get('parse_rate', 0):.1f}%")
        
        # Уникальные IP
        if 'unique_ips' in analysis:
            report.append(f"Уникальных IP: {analysis['unique_ips']}")
        
        # Временной диапазон
        if 'time_range' in analysis:
            time_range = analysis['time_range']
            report.append(f"Период: {time_range['start']} - {time_range['end']}")
        
        # Топ IP адреса
        if 'top_ips' in analysis:
            report.append(f"\n🌐 ТОП IP АДРЕСА")
            for ip, count in list(analysis['top_ips'].items())[:5]:
                report.append(f"  {ip}: {count} запросов")
        
        # Статус коды
        if 'status_codes' in analysis:
            report.append(f"\n📊 СТАТУС КОДЫ")
            for status, count in analysis['status_codes'].items():
                status_name = self.status_codes.get(status, 'Unknown')
                report.append(f"  {status} ({status_name}): {count}")
        
        # HTTP методы
        if 'http_methods' in analysis:
            report.append(f"\n🔗 HTTP МЕТОДЫ")
            for method, count in analysis['http_methods'].items():
                report.append(f"  {method}: {count}")
        
        # Топ пути
        if 'top_paths' in analysis:
            report.append(f"\n📁 ПОПУЛЯРНЫЕ ПУТИ")
            for path, count in list(analysis['top_paths'].items())[:5]:
                report.append(f"  {path}: {count}")
        
        # Аномалии
        if anomalies:
            report.append(f"\n⚠️  АНОМАЛИИ ({len(anomalies)})")
            
            # Группируем по типам
            anomaly_types = defaultdict(list)
            for anomaly in anomalies:
                anomaly_types[anomaly['type']].append(anomaly)
            
            for anomaly_type, items in anomaly_types.items():
                report.append(f"  {anomaly_type}: {len(items)} случаев")
                
                # Показываем первые несколько
                for item in items[:3]:
                    report.append(f"    - {item['message']}")
                
                if len(items) > 3:
                    report.append(f"    ... и еще {len(items) - 3}")
        
        return "\n".join(report)

def main():
    analyzer = LogAnalyzer()
    print("=== АНАЛИЗАТОР ЛОГОВ ===\n")
    
    while True:
        print("1. Анализировать лог-файл")
        print("2. Показать поддерживаемые форматы")
        print("3. Тест парсинга строки")
        print("4. Выход")
        
        choice = input("\nВыберите действие: ")
        
        if choice == "1":
            filename = input("Путь к лог-файлу: ").strip()
            if not filename:
                print("❌ Не указан файл")
                continue
            
            print("Форматы: auto, apache, nginx, common, combined, custom")
            log_format = input("Формат (по умолчанию auto): ").strip() or "auto"
            
            print("🔄 Анализирую лог-файл...")
            entries = analyzer.parse_log_file(filename, log_format)
            
            if entries:
                print(f"✅ Обработано строк: {len(entries)}")
                
                # Анализ
                analysis = analyzer.analyze_entries(entries)
                anomalies = analyzer.detect_anomalies(entries)
                
                # Генерируем отчет
                report = analyzer.generate_report(analysis, anomalies)
                print(f"\n{report}")
                
                # Сохранение отчета
                save_report = input("\nСохранить отчет в файл? (y/n): ")
                if save_report.lower() == 'y':
                    report_filename = input("Имя файла: ") or "log_analysis_report.txt"
                    with open(report_filename, 'w', encoding='utf-8') as f:
                        f.write(report)
                    print(f"✅ Отчет сохранен: {report_filename}")
                
                # Сохранение JSON
                save_json = input("Сохранить данные в JSON? (y/n): ")
                if save_json.lower() == 'y':
                    json_data = {
                        'analysis': analysis,
                        'anomalies': anomalies,
                        'entries_sample': entries[:100]  # Первые 100 записей
                    }
                    
                    json_filename = input("Имя JSON файла: ") or "log_analysis.json"
                    with open(json_filename, 'w', encoding='utf-8') as f:
                        json.dump(json_data, f, ensure_ascii=False, indent=2, default=str)
                    print(f"✅ JSON сохранен: {json_filename}")
            else:
                print("❌ Не удалось обработать файл")
        
        elif choice == "2":
            print("\n📋 ПОДДЕРЖИВАЕМЫЕ ФОРМАТЫ")
            print("=" * 40)
            print("apache  - Apache access log")
            print("nginx   - Nginx access log")
            print("common  - Common Log Format")
            print("combined- Combined Log Format")
            print("custom  - Custom format (timestamp level message)")
            print("auto    - Автоопределение формата")
        
        elif choice == "3":
            log_line = input("Введите строку лога: ").strip()
            if log_line:
                entry = analyzer.parse_log_line(log_line)
                print(f"\n🔍 РЕЗУЛЬТАТ ПАРСИНГА")
                print("=" * 30)
                
                if entry.get('parsed'):
                    print(f"✅ Распознан формат: {entry.get('format', 'unknown')}")
                    for key, value in entry.items():
                        if key not in ['raw_line', 'parsed', 'format']:
                            print(f"{key}: {value}")
                else:
                    print("❌ Не удалось распознать формат")
        
        elif choice == "4":
            break
            
        print("\n" + "="*40 + "\n")

if __name__ == "__main__":
    main()
