import re
import json
import sigma
from .base import SingleTextQueryBackend

class LogPointBackend(SingleTextQueryBackend):
    """Converts Sigma rule into a Datadog query"""
    identifier = "datadog"
    active = True
    config_required = False

    reEscape = re.compile("((?<!\\\\)\\\\|&&|\|\||\\|\\|~|\+|\-|\=|\<|\>|\!|\(|\)|{|}|\[|\]|\^|\"|\“|\”|\*|\?|:|,|/)")
    reClear = None
    andToken = " "
    orToken = " "
    notToken = " -"
    subExpression = "%s"
    listExpression = "(%s)"
    listSeparator = " OR "
    valueExpression = "\"%s\""
    nullExpression = "-%s:*"
    notNullExpression = "%s:*"
    mapExpression = "%s:%s"
    mapListsSpecialHandling = True
    mapListValueExpression = "%s:%s"

    def generateQuery(self, parsed):
        return self.generateNode(parsed.parsedSearch)

    def generateTimeframe(self, timeframe):
        time_unit = timeframe[-1:]
        duration = timeframe[:-1]
        timeframe_in_seconds = 0

        if time_unit == "m":
            timeframe_in_seconds = int(duration) * 60
        elif time_unit == "h":
            timeframe_in_seconds = int(duration) * 3600
        elif time_unit == "d":
            timeframe_in_seconds = int(duration) * 86400
        else:
            timeframe_in_seconds = int(duration)

        return min([0, 60, 300, 600, 900, 1800, 3600, 7200], key=lambda x:abs(x - timeframe_in_seconds))

    def generateAggregation(self, agg):
        if agg == None:
            return
        func = sigma.parser.condition.SigmaAggregationParser
        if agg.aggfunc in [func.AGGFUNC_NEAR, func.AGGFUNC_MIN, func.AGGFUNC_AVG]:
            raise NotImplementedError("The aggregation operator is not yet implemented for this backend")

        if agg.groupfield:
            aggregation = {
                "condition": "a {} {}".format(agg.cond_op, agg.condition),
                "aggregation": agg.aggfunc_notrans,
                "groupByFields": [agg.groupfield],
                "metric": agg.aggfield
            }
        else:
            aggregation = {
                "condition": "a {} {}".format(agg.cond_op, agg.condition),
                "aggregation": agg.aggfunc_notrans,
                "metric": agg.aggfield or ""
            }

        return aggregation

    def mapTags(self, tags):
        mapping = ['security:attack', 'framework:sigma']

        maps = {
                "attack.initial_access": "tactic:TA0001-initial-access",
                "attack.execution": "tactic:TA0002-execution",
                "attack.persistence": "tactic:TA0003-persistence",
                "attack.privilege_escalation": "tactic:TA0004-privilege-escalation",
                "attack.defense_evasion": "tactic:TA0005-defense-evasion",
                "attack.credential_access": "tactic:TA0006-credential-access",
                "attack.discovery": "tactic:TA0007-discovery",
                "attack.lateral_movement": "tactic:TA0008-lateral-movement",
                "attack.collection": "tactic:TA0009-collection",
                "attack.exfiltration": "tactic:TA0010-exfiltration",
                "attack.command_and_control": "tactic:command-and-control",
                "attack.impact": "tactic:TA0040-impact",
                "attack.resouce_development": "tactic:TA0042-resouce_development",
                "attack.reconnaissance": "tactic:TA0043-reconnaissance",
            }

        for tag in tags:
            try:
                mapping.append(maps[tag])
            except KeyError:
                mapping.append(tag.replace('attack.t', 'technique:T', 1).replace('.', '/'))

        return mapping

    def create_rule(self, config):
        rule = {
                "name": config.get("title"),
                "message": "{}\n\n### References:\n{}".format(config.get("description"), "\n".join(config.get("references", ""))),
                "isEnabled": True,
                "tags": self.mapTags(config.get("tags", [])),
                "cases": [{
                    "status": config.get("level", "medium"),
                    "condition": config.get("aggregation", {}).get("condition", "a > 0")
                }],
                "options": {
                    "evaluationWindow": self.generateTimeframe(config.get("detection", {}).get("timeframe", "300s")),
                    "maxSignalDuration": 3600,
                    "keepAlive": 3600
                },
                "queries": [{
                  "query": "source:{} {}".format(config.get("logsource", {}).get("product", "*"), config.get("translation")),
                  "aggregation": config.get("aggregation", {}).get("aggregation", "count"),
                  "metric": config.get("aggregation", {}).get("metric", "")
                }]
            }

        if config.get("aggregation", {}).get("groupByFields", []):
            rule["queries"][-1].update({
                "groupByFields": config.get("aggregation", {}).get("groupByFields")
            })

        if config.get("logsource", {}).get("product"):
            rule["tags"].append("scope:{}".format(config.get("logsource").get("product")))

        if config.get("logsource", {}).get("source"):
            rule["tags"].append("source:{}".format(config.get("logsource").get("source")))

        if config.get("logsource", {}).get("service"):
            rule["tags"].append("service:{}".format(config.get("logsource").get("service")))

        return rule

    def generate(self, sigmaparser):
        translation = super().generate(sigmaparser)
        configs = sigmaparser.parsedyaml

        for parsed in sigmaparser.condparsed:
            if parsed.parsedAgg:
                configs.update({"aggregation": self.generateAggregation(parsed.parsedAgg)})

        if translation:
            configs.update({"translation": translation})
            rule = self.create_rule(configs)
            return json.dumps(rule, indent=2)
        else:
            raise NotSupportedError("No table could be determined from Sigma rule")

