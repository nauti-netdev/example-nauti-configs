import json
from nauti.auditor import Auditor


@Auditor.register('netbox', 'clearpass', 'devices')
class Nb2CPDevicesAuditor(Auditor):
    fields = ('hostname', 'os_name', 'site', 'ipaddr')
    key_fields = ('hostname', )

    def origin_fetch_filter(self):
        filter_params = {
            'has_primary_ip': 'true'
        }
        filter_params.update(self.options.get('extras', {}))
        return filter_params

    def origin_key_filter(self, item: dict) -> bool:
        if item['status'] not in ['active', 'offline', 'staged', 'planned']:
            return False

        if item['vendor'] in ['pan', 'meraki']:
            return False

        return True

    def target_fetch_filter(self):
        if (site := self.options['extras'].get('site')) is not None:
            return {'filter': json.dumps({'Location': site})}

        return None
