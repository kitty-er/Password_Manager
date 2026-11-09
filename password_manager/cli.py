import argparse
import getpass
from pathlib import Path

from password_manager.manager import PasswordManager


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Локальный менеджер паролей")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--init", action="store_true", help="создать хранилище")
    mode.add_argument("--unlock", action="store_true", help="открыть хранилище")
    parser.add_argument(
        "--generate",
        action="store_true",
        help="сгенерировать надёжный пароль",
    )
    parser.add_argument(
        "--length",
        type=int,
        default=20,
        help="длина генерируемого пароля (по умолчанию 20)",
    )
    return parser


def run_menu(manager: PasswordManager) -> None:
    while True:
        print("\n===== PASSWORD MANAGER =====")
        print("1. Добавить запись")
        print("2. Показать список сайтов")
        print("3. Получить пароль")
        print("4. Удалить запись")
        print("5. Сгенерировать пароль")
        print("6. Выйти")
        choice = input("Выберите действие: ").strip()
        try:
            if choice == "1":
                name = input("Название сайта: ").strip()
                login = input("Логин: ").strip()
                password = getpass.getpass("Пароль: ")
                manager.add_entry(name, login, password)
                print("Запись сохранена.")
            elif choice == "2":
                names = manager.list_entries()
                if not names:
                    print("Хранилище пустое.")
                else:
                    for name in names:
                        print(f"- {name}")
            elif choice == "3":
                name = input("Название сайта: ").strip()
                master_password = getpass.getpass("Повторите мастер-пароль: ")
                if not manager.unlock(master_password):
                    print("Неверный мастер-пароль.")
                    continue
                entry = manager.get_entry(name)
                if entry is None:
                    print("Запись не найдена.")
                else:
                    print(f"Логин: {entry['login']}")
                    print(f"Пароль: {entry['password']}")
            elif choice == "4":
                name = input("Название сайта для удаления: ").strip()
                if manager.delete_entry(name):
                    print("Запись удалена.")
                else:
                    print("Запись не найдена.")
            elif choice == "5":
                print(PasswordManager.generate_password())
            elif choice == "6":
                print("До свидания!")
                break
            else:
                print("Выбери пункт от 1 до 6.")
        except (ValueError, RuntimeError, OSError) as error:
            print(f"Ошибка: {error}")


def main() -> None:
    args = build_parser().parse_args()
    if args.generate:
        try:
            print(PasswordManager.generate_password(args.length))
        except ValueError as error:
            print(f"Ошибка: {error}")
        return
    manager = PasswordManager()
    vault_exists = Path("vault.json").exists()
    if args.init or (not args.unlock and not vault_exists):
        password = getpass.getpass("Придумайте мастер-пароль: ")
        confirmation = getpass.getpass("Повторите мастер-пароль: ")
        if password != confirmation:
            print("Пароли не совпадают.")
            return
        try:
            manager.init_master(password)
            print("Хранилище создано.")
        except (ValueError, FileExistsError, OSError) as error:
            print(f"Ошибка: {error}")
            return
    else:
        password = getpass.getpass("Введите мастер-пароль: ")
        if not manager.unlock(password):
            print("Не удалось войти. Проверьте пароль или файл хранилища.")
            return
        print("Вход выполнен.")
    run_menu(manager)


if __name__ == "__main__":
    main()
