import sys


def main() -> int:
    from .memory import tune
    tune()
    argv = sys.argv[1:]
    from .cli import COMMANDS, main as cli_main
    if argv and (argv[0] in COMMANDS or argv[0] in ("-h", "--help", "--version")):
        return cli_main(argv)
    from .viewer import run_gui
    if argv and argv[0] == "--encrypt":  # из контекстного меню файлового менеджера
        return run_gui(sys.argv[:1], encrypt=argv[1:])
    return run_gui(sys.argv[:1] + argv)


if __name__ == "__main__":
    sys.exit(main())
