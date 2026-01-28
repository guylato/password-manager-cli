import argparse

from . import database
from . import cli


def build_parser() -> argparse.ArgumentParser:
    """
    Construit le parseur de ligne de commande pour respecter :
    - passmanager -r <username>
    - passmanager -u <username> -a <label> <password>
    - passmanager -u <username> -s <label>
    """
    parser = argparse.ArgumentParser(
        description="Simple password manager CLI."
    )

    # Enregistrer un nouvel utilisateur
    parser.add_argument(
        "-r",
        metavar="USERNAME",
        dest="register_username",
        help="register a new user",
    )

    # Nom d'utilisateur pour les opérations add/show
    parser.add_argument(
        "-u",
        metavar="USERNAME",
        dest="username",
        help="username to use for add/show operations",
    )

    # Ajouter un mot de passe
    parser.add_argument(
        "-a",
        metavar="LABEL",
        dest="add_label",
        help="add a password with given label",
    )

    # Afficher un mot de passe
    parser.add_argument(
        "-s",
        metavar="LABEL",
        dest="show_label",
        help="show password for given label",
    )

    # Mot de passe en clair (utilisé uniquement avec -a)
    parser.add_argument(
        "password",
        nargs="?",
        help="password to store (used with -a)",
    )

    return parser


def main() -> None:
    # Initialise la base de données (création des tables si besoin)
    database.init_db()

    parser = build_parser()
    args = parser.parse_args()

    # Mode enregistrement d'un nouvel utilisateur : -r <username>
    if args.register_username:
        if args.username or args.add_label or args.show_label or args.password:
            print("Error: -r cannot be combined with other options.")
            return
        cli.register_user(args.register_username)
        return

    # Modes nécessitant -u <username>
    if args.username:
        username = args.username

        # Ajouter un mot de passe : -u <username> -a <label> <password>
        if args.add_label:
            label = args.add_label
            if not args.password:
                print("Error: password value is required when using -a.")
                return
            cli.add_password(username, label, args.password)
            return

        # Afficher un mot de passe : -u <username> -s <label>
        if args.show_label:
            label = args.show_label
            cli.show_password(username, label)
            return

        print("Error: must use -a <label> <password> or -s <label> with -u <username>.")
        return

    # Si aucun argument pertinent n'est fourni, on affiche l'aide
    parser.print_help()


if __name__ == "__main__":
    main()
