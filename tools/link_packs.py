"""
Converts old pack.yml format into the new one and symlinks all
rules of the pack into the pack itself for easier zipping and usage.
"""

from collections.abc import Iterable
from io import StringIO
from itertools import chain
from os.path import relpath
from pathlib import Path
from typing import TypedDict

from ruamel.yaml import YAML
from yaml import safe_load

DIR_ROOT = Path(__file__).parent.parent
DIR_PACKS = DIR_ROOT / "packs"
DIR_RULES = DIR_ROOT / "rules"


class Rules(TypedDict):
    sigma: list[str]
    yara: list[str]
    ioc: list[str]


def find_by_content(root: Path, content: str, glob: str = "*") -> Iterable[Path]:
    for file in root.rglob(glob):
        if file.is_file():
            try:
                text = file.read_text()
                if content in text:
                    yield file
            except Exception as e:
                print(f"Error reading {file}: {e}")


def symlink(original: Path, target: Path):
    if target.is_symlink():
        target.unlink()
    target.parent.mkdir(parents=True, exist_ok=True)
    link = Path(relpath(original.absolute(), start=target.parent.absolute()))
    target.symlink_to(link)


def main():
    ryaml = YAML()
    ryaml.preserve_quotes = True
    ryaml.width = 120
    ryaml.indent(mapping=4, sequence=2, offset=2)

    for file_pack in DIR_PACKS.rglob("pack.yml"):
        print(f"[*] Checking {file_pack}")
        pack = ryaml.load(file_pack.read_text(encoding="utf-8"))

        modified = False

        rules = pack.get("rules")
        if isinstance(rules, list):
            print("[*] Converting rules list to dict")
            rules_ids = [str(x) for x in rules]
            rules_by_category: dict[str, list[str]] = {
                "sigma": [],
                "yara": [],
                "ioc": [],
            }
            for rule_id in rules_ids:
                rule_path = next(
                    chain(
                        find_by_content(DIR_RULES, rule_id, glob="*.yml"),
                        find_by_content(DIR_RULES, rule_id, glob="*.yaml"),
                        find_by_content(DIR_RULES, rule_id, glob="*.yar"),
                    )
                )
                print(f"    [*] Found rule {rule_id} in {rule_path}")
                rule_type = rule_path.relative_to(DIR_RULES).parts[0]
                rules_by_category[rule_type].append(rule_id)
            for key in [x for x in rules_by_category if not rules_by_category[x]]:
                del rules_by_category[key]
            pack["rules"] = {"has": rules_by_category}
            modified = True

        sources = pack.get("sources")
        if isinstance(sources, list):
            print("[*] Converting sources list to dict")
            pack["sources"] = {"manual": list(sources)}
            modified = True

        if modified:
            out = StringIO()
            ryaml.dump(pack, out)
            dumped = out.getvalue()
            dumped_lines = [line.rstrip() for line in dumped.splitlines()]
            file_pack.write_text("\n".join(dumped_lines) + "\n", encoding="utf-8")
            pack = ryaml.load(file_pack.read_text(encoding="utf-8"))

        rules_dict = pack.get("rules") or {}
        has_dict = rules_dict.get("has") or {}

        for category, rule_ids in has_dict.items():
            if category == "sigma":
                for rule_id in rule_ids:
                    path_rule = next(
                        chain(
                            find_by_content(DIR_RULES, rule_id, glob="*.yml"),
                            find_by_content(DIR_RULES, rule_id, glob="*.yaml"),
                        )
                    )
                    path_rule_link = file_pack.parent / category / path_rule.name
                    symlink(path_rule, path_rule_link)
                    print(f"    [*] Linked {rule_id} to {path_rule_link}")
            elif category == "yara":
                for rule_id in rule_ids:
                    path_rule = next(chain(find_by_content(DIR_RULES, rule_id, glob="*.yar")))
                    path_rule_link = file_pack.parent / category / path_rule.name
                    symlink(path_rule, path_rule_link)
                    print(f"    [*] Linked {rule_id} to {path_rule_link}")
            elif category == "ioc":
                iocs: dict[str, list[str]] = {}
                for rule_id in rule_ids:
                    path_rule = next(
                        chain(
                            find_by_content(DIR_RULES, rule_id, glob="*.yml"),
                            find_by_content(DIR_RULES, rule_id, glob="*.yaml"),
                        )
                    )
                    rule = safe_load(path_rule.read_text())
                    rule_severity = rule.get("severity")
                    for indicator_type, indicators in rule["indicators"].items():
                        if indicator_type not in iocs:
                            iocs[indicator_type] = []
                        for indicator in indicators:
                            if isinstance(indicator, dict):
                                ioc_value = indicator["value"]
                                ioc_comment = indicator.get("comment")
                            else:
                                ioc_value = indicator
                                ioc_comment = None
                            ioc_comment_parts: list[str] = [f"rule={rule_id}"]
                            if rule_severity:
                                ioc_comment_parts.append(f"severity={rule_severity}")
                            if ioc_comment:
                                ioc_comment_parts.append(f"comment={ioc_comment}")
                            ioc_comment_str = " ".join(ioc_comment_parts)
                            iocs[indicator_type].append(f"{ioc_value};{ioc_comment_str}")
                for ioc_type, ioc_values in iocs.items():
                    path_rule = file_pack.parent / category / f"{ioc_type}.txt"
                    path_rule.parent.mkdir(parents=True, exist_ok=True)
                    path_rule.write_text("\n".join(ioc_values))
                    print(f"    [*] Written {len(ioc_values)} {ioc_type} IOCs to {path_rule}")


if __name__ == "__main__":
    main()
