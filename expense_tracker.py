import json
import datetime
from typing import List, Dict, Optional
from collections import defaultdict
import calendar


class ExpenseTracker:
    """
    Продвинутый трекер личных финансов с категориями,
    бюджетированием и аналитикой
    """
    
    def __init__(self, username: str):
        self.username = username
        self.transactions = []
        self.categories = {
            'income': ['Зарплата', 'Фриланс', 'Инвестиции', 'Подарки', 'Прочее'],
            'expense': ['Продукты', 'Транспорт', 'Жилье', 'Развлечения', 
                       'Здоровье', 'Образование', 'Одежда', 'Связь', 'Прочее']
        }
        self.budgets = {}
        self.currency = "RUB"
        self.savings_goal = 0
        
    def add_income(self, amount: float, category: str, description: str, 
                   date: Optional[str] = None):
        """Добавление дохода"""
        if category not in self.categories['income']:
            return f"Ошибка: категория '{category}' не существует"
        
        transaction_date = date if date else datetime.datetime.now().strftime('%Y-%m-%d')
        
        transaction = {
            'id': len(self.transactions) + 1,
            'type': 'income',
            'amount': amount,
            'category': category,
            'description': description,
            'date': transaction_date,
            'timestamp': datetime.datetime.now().isoformat()
        }
        
        self.transactions.append(transaction)
        return f"Доход добавлен: {amount} {self.currency} - {category}"
    
    def add_expense(self, amount: float, category: str, description: str,
                    date: Optional[str] = None, payment_method: str = "Наличные"):
        """Добавление расхода"""
        if category not in self.categories['expense']:
            return f"Ошибка: категория '{category}' не существует"
        
        transaction_date = date if date else datetime.datetime.now().strftime('%Y-%m-%d')
        
        transaction = {
            'id': len(self.transactions) + 1,
            'type': 'expense',
            'amount': amount,
            'category': category,
            'description': description,
            'date': transaction_date,
            'payment_method': payment_method,
            'timestamp': datetime.datetime.now().isoformat()
        }
        
        self.transactions.append(transaction)
        
        # Проверка бюджета
        budget_warning = self._check_budget(category, transaction_date)
        
        return f"Расход добавлен: {amount} {self.currency} - {category}" + \
               (f"\n{budget_warning}" if budget_warning else "")
    
    def add_category(self, transaction_type: str, category_name: str):
        """Добавление новой категории"""
        if transaction_type not in ['income', 'expense']:
            return "Ошибка: тип должен быть 'income' или 'expense'"
        
        if category_name not in self.categories[transaction_type]:
            self.categories[transaction_type].append(category_name)
            return f"Категория '{category_name}' добавлена в {transaction_type}"
        
        return f"Категория '{category_name}' уже существует"
    
    def set_budget(self, category: str, monthly_limit: float):
        """Установка месячного бюджета для категории"""
        if category not in self.categories['expense']:
            return f"Ошибка: категория '{category}' не найдена"
        
        self.budgets[category] = monthly_limit
        return f"Бюджет для '{category}' установлен: {monthly_limit} {self.currency}/месяц"
    
    def _check_budget(self, category: str, date: str) -> Optional[str]:
        """Проверка превышения бюджета"""
        if category not in self.budgets:
            return None
        
        year, month = date.split('-')[:2]
        monthly_expenses = self.get_expenses_by_category(category, int(year), int(month))
        
        budget_limit = self.budgets[category]
        percentage = (monthly_expenses / budget_limit * 100) if budget_limit > 0 else 0
        
        if percentage >= 100:
            return f"⚠️ ВНИМАНИЕ: Бюджет категории '{category}' превышен на {percentage - 100:.1f}%!"
        elif percentage >= 80:
            return f"⚠️ ПРЕДУПРЕЖДЕНИЕ: Использовано {percentage:.1f}% бюджета категории '{category}'"
        
        return None
    
    def delete_transaction(self, transaction_id: int):
        """Удаление транзакции по ID"""
        for i, transaction in enumerate(self.transactions):
            if transaction['id'] == transaction_id:
                deleted = self.transactions.pop(i)
                return f"Транзакция удалена: {deleted['description']}"
        
        return f"Транзакция с ID {transaction_id} не найдена"
    
    def get_total_income(self, year: Optional[int] = None, 
                        month: Optional[int] = None) -> float:
        """Расчет общего дохода за период"""
        total = 0
        for transaction in self.transactions:
            if transaction['type'] == 'income':
                if self._date_matches(transaction['date'], year, month):
                    total += transaction['amount']
        return total
    
    def get_total_expenses(self, year: Optional[int] = None,
                          month: Optional[int] = None) -> float:
        """Расчет общих расходов за период"""
        total = 0
        for transaction in self.transactions:
            if transaction['type'] == 'expense':
                if self._date_matches(transaction['date'], year, month):
                    total += transaction['amount']
        return total
    
    def _date_matches(self, date_str: str, year: Optional[int], 
                     month: Optional[int]) -> bool:
        """Проверка соответствия даты периоду"""
        date_parts = date_str.split('-')
        
        if year is not None and int(date_parts[0]) != year:
            return False
        
        if month is not None and int(date_parts[1]) != month:
            return False
        
        return True
    
    def get_expenses_by_category(self, category: str, year: Optional[int] = None,
                                 month: Optional[int] = None) -> float:
        """Расчет расходов по категории"""
        total = 0
        for transaction in self.transactions:
            if (transaction['type'] == 'expense' and 
                transaction['category'] == category and
                self._date_matches(transaction['date'], year, month)):
                total += transaction['amount']
        return total
    
    def get_balance(self, year: Optional[int] = None, 
                   month: Optional[int] = None) -> float:
        """Расчет баланса (доходы - расходы)"""
        income = self.get_total_income(year, month)
        expenses = self.get_total_expenses(year, month)
        return income - expenses
    
    def get_category_breakdown(self, transaction_type: str, 
                              year: Optional[int] = None,
                              month: Optional[int] = None) -> Dict[str, float]:
        """Разбивка по категориям"""
        breakdown = defaultdict(float)
        
        for transaction in self.transactions:
            if (transaction['type'] == transaction_type and
                self._date_matches(transaction['date'], year, month)):
                breakdown[transaction['category']] += transaction['amount']
        
        return dict(breakdown)
    
    def get_spending_trend(self, months: int = 6) -> Dict[str, float]:
        """Анализ тренда расходов за последние N месяцев"""
        today = datetime.datetime.now()
        trend = {}
        
        for i in range(months):
            date = today - datetime.timedelta(days=30 * i)
            month_key = date.strftime('%Y-%m')
            expenses = self.get_total_expenses(date.year, date.month)
            trend[month_key] = expenses
        
        return dict(sorted(trend.items()))
    
    def set_savings_goal(self, goal_amount: float):
        """Установка цели по накоплениям"""
        self.savings_goal = goal_amount
        return f"Цель по накоплениям установлена: {goal_amount} {self.currency}"
    
    def get_savings_progress(self) -> Dict[str, float]:
        """Прогресс по накоплениям"""
        total_balance = self.get_balance()
        
        if self.savings_goal == 0:
            return {
                'current_savings': total_balance,
                'goal': 0,
                'progress_percentage': 0,
                'remaining': 0
            }
        
        progress = (total_balance / self.savings_goal * 100) if self.savings_goal > 0 else 0
        
        return {
            'current_savings': total_balance,
            'goal': self.savings_goal,
            'progress_percentage': progress,
            'remaining': self.savings_goal - total_balance
        }
    
    def generate_monthly_report(self, year: int, month: int) -> str:
        """Генерация месячного отчета"""
        month_name = calendar.month_name[month]
        
        report = []
        report.append(f"{'='*60}")
        report.append(f"ФИНАНСОВЫЙ ОТЧЕТ: {month_name} {year}")
        report.append(f"Пользователь: {self.username}")
        report.append(f"{'='*60}\n")
        
        income = self.get_total_income(year, month)
        expenses = self.get_total_expenses(year, month)
        balance = income - expenses
        
        report.append("СВОДКА:")
        report.append(f"Доходы: {income:.2f} {self.currency}")
        report.append(f"Расходы: {expenses:.2f} {self.currency}")
        report.append(f"Баланс: {balance:.2f} {self.currency}\n")
        
        expense_breakdown = self.get_category_breakdown('expense', year, month)
        if expense_breakdown:
            report.append("РАСХОДЫ ПО КАТЕГОРИЯМ:")
            for category, amount in sorted(expense_breakdown.items(), 
                                          key=lambda x: x[1], reverse=True):
                percentage = (amount / expenses * 100) if expenses > 0 else 0
                report.append(f"{category}: {amount:.2f} {self.currency} ({percentage:.1f}%)")
                
                if category in self.budgets:
                    budget = self.budgets[category]
                    budget_used = (amount / budget * 100) if budget > 0 else 0
                    report.append(f"  Бюджет: {budget:.2f} (использовано {budget_used:.1f}%)")
        
        report.append(f"\n{'='*60}")
        
        return "\n".join(report)
    
    def export_to_json(self, filename: str):
        """Экспорт данных в JSON"""
        data = {
            'username': self.username,
            'currency': self.currency,
            'categories': self.categories,
            'budgets': self.budgets,
            'savings_goal': self.savings_goal,
            'transactions': self.transactions
        }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=4)
        
        return f"Данные экспортированы в {filename}"
    
    def import_from_json(self, filename: str):
        """Импорт данных из JSON"""
        with open(filename, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        self.username = data.get('username', self.username)
        self.currency = data.get('currency', self.currency)
        self.categories = data.get('categories', self.categories)
        self.budgets = data.get('budgets', self.budgets)
        self.savings_goal = data.get('savings_goal', self.savings_goal)
        self.transactions = data.get('transactions', self.transactions)
        
        return f"Данные импортированы из {filename}"


# Пример использования
if __name__ == "__main__":
    tracker = ExpenseTracker("Иван Петров")
    
    # Добавление доходов
    tracker.add_income(75000, "Зарплата", "Зарплата за октябрь", "2024-10-01")
    tracker.add_income(15000, "Фриланс", "Разработка сайта", "2024-10-10")
    
    # Установка бюджетов
    tracker.set_budget("Продукты", 20000)
    tracker.set_budget("Транспорт", 5000)
    tracker.set_budget("Развлечения", 10000)
    
    # Добавление расходов
    tracker.add_expense(5500, "Продукты", "Магазин Пятерочка", "2024-10-02")
    tracker.add_expense(1200, "Транспорт", "Метро и автобус", "2024-10-03")
    tracker.add_expense(3000, "Развлечения", "Кино и ресторан", "2024-10-05")
    
    # Генерация отчета
    print(tracker.generate_monthly_report(2024, 10))
