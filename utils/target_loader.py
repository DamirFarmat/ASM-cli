"""
Утилита для загрузки целей из файла
"""

import os
from typing import List

class TargetLoader:
    def __init__(self):
        self.supported_extensions = ['.txt', '.csv']
    
    def load_targets(self, file_path: str) -> List[str]:
        """
        Загружает цели из файла
        
        Args:
            file_path: Путь к файлу с целями
            
        Returns:
            Список целей
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Файл {file_path} не найден")
        
        file_ext = os.path.splitext(file_path)[1].lower()
        if file_ext not in self.supported_extensions:
            raise ValueError(f"Неподдерживаемый формат файла: {file_ext}")
        
        targets = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # Убираем комментарии в конце строки
                        if '#' in line:
                            line = line.split('#')[0].strip()
                        if line:
                            targets.append(line)
        except UnicodeDecodeError:
            # Пробуем другие кодировки
            try:
                with open(file_path, 'r', encoding='cp1251') as f:
                    for line_num, line in enumerate(f, 1):
                        line = line.strip()
                        if line and not line.startswith('#'):
                            if '#' in line:
                                line = line.split('#')[0].strip()
                            if line:
                                targets.append(line)
            except UnicodeDecodeError:
                raise ValueError(f"Не удается прочитать файл {file_path}. Проверьте кодировку.")
        
        # Убираем дубликаты, сохраняя порядок
        seen = set()
        unique_targets = []
        for target in targets:
            if target not in seen:
                seen.add(target)
                unique_targets.append(target)
        
        return unique_targets
    
    def validate_targets(self, targets: List[str]) -> tuple[List[str], List[str]]:
        """
        Валидирует список целей
        
        Args:
            targets: Список целей
            
        Returns:
            Кортеж (валидные цели, невалидные цели)
        """
        valid = []
        invalid = []
        
        for target in targets:
            if self._is_valid_target(target):
                valid.append(target)
            else:
                invalid.append(target)
        
        return valid, invalid
    
    def _is_valid_target(self, target: str) -> bool:
        """
        Проверяет валидность цели
        
        Args:
            target: Цель для проверки
            
        Returns:
            True если цель валидна
        """
        if not target or not target.strip():
            return False
        
        # Простые проверки
        target = target.strip()
        
        # Проверка на IP адрес
        if self._is_valid_ip(target):
            return True
        
        # Проверка на домен
        if self._is_valid_domain(target):
            return True
        
        return False
    
    def _is_valid_ip(self, target: str) -> bool:
        """Проверяет, является ли цель валидным IP адресом"""
        import re
        
        # IPv4
        ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(ipv4_pattern, target):
            parts = target.split('.')
            return all(0 <= int(part) <= 255 for part in parts)
        
        # IPv6 (упрощенная проверка)
        ipv6_pattern = r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$'
        if re.match(ipv6_pattern, target):
            return True
        
        return False
    
    def _is_valid_domain(self, target: str) -> bool:
        """Проверяет, является ли цель валидным доменом"""
        import re
        
        # Простая проверка на домен
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        return bool(re.match(domain_pattern, target))
