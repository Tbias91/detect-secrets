import argparse
import json
import os
import sys
import textwrap
from typing import List
from typing import Optional

from detect_secrets.__version__ import VERSION
from detect_secrets.core import baseline
from detect_secrets.core.log import log
from detect_secrets.core.secrets_collection import SecretsCollection
from detect_secrets.core.usage import ParserBuilder
from detect_secrets.util import color
from detect_secrets.util import git


def main(argv: Optional[List[str]] = None) -> int:
    try:
        args = parse_args(argv)
    except ValueError:
        return 1

    if args.verbose:    # pragma: no cover
        log.set_debug_level(args.verbose)

    # Find all secrets in files to be committed
    secrets = SecretsCollection()
    for filename in args.filenames:
        secrets.scan_file(filename)

    new_secrets = secrets
    if args.baseline:
        new_secrets = secrets - args.baseline

    if new_secrets:
        if args.json:
            print(json.dumps(baseline.format_for_output(new_secrets), indent=2))
        else:
            pretty_print_diagnostics(new_secrets)
        return 1

    if not args.baseline:
        return 0

    # Only attempt baseline modifications if we don't find any new secrets.
    is_modified = should_update_baseline(
        args.baseline,
        scanned_results=secrets,
        filelist=args.filenames,
        baseline_version=args.baseline_version,
    )

    if is_modified:
        if args.baseline_version != VERSION:
            with open(args.baseline_filename) as f:
                old_baseline = json.loads(f.read())

            # Override the results, because this has been updated in `should_update_baseline`.
            old_baseline['results'] = args.baseline.json()

            args.baseline = baseline.upgrade(old_baseline)

        baseline.save_to_file(args.baseline, filename=args.baseline_filename)
        print(
            'The baseline file was updated.\n'
            'Probably to keep line numbers of secrets up-to-date.\n'
            'Please `git add {}`, thank you.\n\n'.format(args.baseline_filename),
        )
        return 3

    return 0


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    """
    :raises: ValueError
    """
    output = ParserBuilder().add_pre_commit_arguments().parse_args(argv)
    if output.baseline:
        raise_exception_if_baseline_file_is_unstaged(output.baseline_filename)

    return output


def raise_exception_if_baseline_file_is_unstaged(filename: str) -> None:
    """
    We want to make sure that if there are changes to the baseline
    file, they will be included in the commit. This way, we can keep
    our baselines up-to-date.

    :raises: ValueError
    """
    if filename in git.get_changed_but_unstaged_files():
        print(
            f'Your baseline file ({filename}) is unstaged.\n'
            f'`git add {filename}` to fix this.',
        )
        raise ValueError


def should_update_baseline(
    secrets: SecretsCollection,
    scanned_results: SecretsCollection,
    filelist: List[str],
    baseline_version: str,
) -> bool:
    """
    :returns: True if changes occurred.
    """
    original = SecretsCollection.load_from_baseline({'results': secrets.json()})

    secrets.trim(scanned_results=scanned_results, filelist=filelist)

    if baseline_version != VERSION:
        return True

    if not secrets.exactly_equals(original):
        return True

    return False


def pretty_print_diagnostics(secrets: SecretsCollection, width: int = 80) -> None:
    # Header
    print(
        textwrap.fill(
            color.colorize(
                'ERROR: Potential secrets about to be committed to git repo!',
                color.AnsiColor.RED,
            ),
            width=width,
        ),
    )
    print()

    # Display found secrets
    for _, secret in secrets:
        print(secret)

    # Display the number of detected secrets
    print(f'\nTotal secrets detected: {len(secrets)}')

    # Display mitigation suggestions
    print('Possible mitigations:')
    wrapper = textwrap.TextWrapper(
        initial_indent='  - ',
        subsequent_indent='    ',
        width=width,
    )
    for suggestion in [
        'For information about putting your secrets in a safer place, '
        'please ask {0}'.format(os.environ.get('DETECT_SECRETS_SECURITY_TEAM', 'in #security')),

        'Mark false positives with an inline '
        '`{0}` comment'.format(color.colorize('pragma: allowlist secret', color.AnsiColor.BOLD)),
    ]:
        print(wrapper.fill(suggestion))

    print()
    print(
        textwrap.fill(
            'If a secret has already been committed, visit '
            'https://help.github.com/articles/removing-sensitive-data-from-a-repository',
            width=width,
        ),
    )


if __name__ == '__main__':
    sys.exit(main())
