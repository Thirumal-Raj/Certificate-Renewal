import sys
from pathlib import Path

import yaml

from gmail_agent import GmailAgent


def load_config(path: str = "config/config.yaml") -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


def main():
    print("Certificate Renewal System")

    config_path = Path(__file__).parent.parent / "config" / "config.yaml"
    config = load_config(str(config_path))

    agent = GmailAgent(config)
    try:
        downloaded = agent.run()
    except EnvironmentError as e:
        print(f"\n[error] {e}", file=sys.stderr)
        sys.exit(1)

    if downloaded:
        print("\nDownloaded files:")
        for f in downloaded:
            print(f"  {f}")


if __name__ == "__main__":
    main()
