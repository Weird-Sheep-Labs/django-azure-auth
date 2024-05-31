import json


class EntraStateSerializer:
    def serialize(self, **kwargs):
        return json.dumps(kwargs)

    def deserialize(self, state: str):
        try:
            return json.loads(state)
        except json.JSONDecodeError:
            return {}
