from sarif_om import *

from src.output_parser.SarifHolder import isNotDuplicateRule, parseArtifact, parseRule, parseResult


class Sailfish:

    def parseSarif(self, sailfish_output_results, file_path_in_repo):
        results_list = []
        rules_list = []

        analysis = sailfish_output_results["analysis"]
        dependency_info = analysis["dependency_info"]

        for _, entries in dependency_info.items():
            for entry in entries:
                vulnerability = entry["attack_type"]
                rule = parseRule(tool="sailfish", vulnerability=vulnerability)
                result = parseResult(tool="sailfish", vulnerability=vulnerability, level="warning", uri=file_path_in_repo)
                results_list.append(result)
                if isNotDuplicateRule(rule, rules_list):
                    rules_list.append(rule)

        artifact = parseArtifact(uri=file_path_in_repo)

        tool = Tool(driver=ToolComponent(name="Sailfish", rules=rules_list,
                                         information_uri="https://github.com/ucsb-seclab/sailfish",
                                         full_description=MultiformatMessageString(
                                             text="Sailfish detects state-inconsistency bugs such as transaction order dependence in Solidity smart contracts.")))

        run = Run(tool=tool, artifacts=[artifact], results=results_list)

        return run
