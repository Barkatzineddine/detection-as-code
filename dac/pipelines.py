"""Processing pipelines that map this repository's field names to SIEM schemas.

Windows rules use the Sysmon / Windows event field names of the Sigma taxonomy. Linux SSH
rules use the fields produced by ``dac.sshd``. These pipelines rename them for:

* Wazuh: the ``wazuh-alerts-*`` index, where the eventchannel decoder stores Windows
  events under ``data.win.system.*`` and ``data.win.eventdata.*`` (lowerCamelCase) and the
  sshd decoder fills ``data.srcip`` and ``data.dstuser``.
* Elastic: ECS, as written by Filebeat's ``system/auth`` module. Windows is handled by
  pySigma's own ``ecs_windows`` pipeline.
"""

from __future__ import annotations

from sigma.processing.conditions import LogsourceCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import (
    FieldFunctionTransformation,
    FieldMappingTransformation,
)


# Conditions are bound to the pipeline that uses them, so each pipeline gets new ones.
def _sshd():
    return [LogsourceCondition(product="linux", service="sshd")]


def _windows():
    return [LogsourceCondition(product="windows")]


WAZUH_WINDOWS_SYSTEM_FIELDS = {
    "EventID": "data.win.system.eventID",
    "Channel": "data.win.system.channel",
    "Computer": "data.win.system.computer",
    "Hostname": "data.win.system.computer",
    "Provider_Name": "data.win.system.providerName",
}

WAZUH_SSHD_FIELDS = {
    "process": "predecoder.program_name",
    "host": "predecoder.hostname",
    "message": "full_log",
    "src_ip": "data.srcip",
    "src_port": "data.srcport",
    "user": "data.dstuser",
}

ECS_SSHD_FIELDS = {
    "process": "process.name",
    "host": "host.hostname",
    "message": "message",
    "src_ip": "source.ip",
    "src_port": "source.port",
    "user": "user.name",
}


def _wazuh_eventdata(field: str | None) -> str | None:
    if not field:
        return field
    return "data.win.eventdata." + field[0].lower() + field[1:]


def wazuh_pipeline() -> ProcessingPipeline:
    return ProcessingPipeline(
        name="Wazuh indexer field mapping",
        priority=100,
        items=[
            ProcessingItem(
                identifier="wazuh_windows_fields",
                transformation=FieldFunctionTransformation(
                    transform_func=_wazuh_eventdata, mapping=WAZUH_WINDOWS_SYSTEM_FIELDS
                ),
                rule_conditions=_windows(),
            ),
            ProcessingItem(
                identifier="wazuh_sshd_fields",
                transformation=FieldMappingTransformation(WAZUH_SSHD_FIELDS),
                rule_conditions=_sshd(),
            ),
        ],
    )


def ecs_sshd_pipeline() -> ProcessingPipeline:
    return ProcessingPipeline(
        name="ECS mapping for OpenSSH (Filebeat system/auth)",
        priority=100,
        items=[
            ProcessingItem(
                identifier="ecs_sshd_fields",
                transformation=FieldMappingTransformation(ECS_SSHD_FIELDS),
                rule_conditions=_sshd(),
            )
        ],
    )
