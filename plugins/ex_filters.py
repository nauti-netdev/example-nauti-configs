from nauti.tasks import DiffCollectionsFilter
from nauti.collections.devices import DeviceCollection


@DiffCollectionsFilter.register('netbox', 'clearpass', 'devices')
class Nb2CPDevicesFilter(DiffCollectionsFilter):
    fields = ('hostname', 'os_name', 'site', 'ipaddr')
    key_fields = ('hostname', )

    def origin_fetch_filter(self):
        return {
            'platform__n': 'null',
            'has_primary_ip': 'true'
        }

    def origin_key_filter(self, item: dict) -> bool:
        if item['status'] not in ['active', 'offline', 'staged', 'planned']:
            return False

        if item['vendor'] == 'pan':
            return False

        return True


@DiffCollectionsFilter.register('ipfabric', 'netbox', 'devices')
class IPFabricToNetboxDevicesFilter(DiffCollectionsFilter):
    fields = set(DeviceCollection.FIELDS) - {'model', 'ipaddr'}
    key_fields = ('hostname', )

    def origin_key_filter(self, item: dict):
        # ignore Cisco APs and Palo FW devices
        if item['os_name'] in ['lap', 'pan-os']:
            return False

        return True

    def target_key_filter(self, item: dict):
        """ only include items that are present in the origin source """
        return item['hostname'] in self.origin.items


@DiffCollectionsFilter.register('ipfabric', 'netbox', 'devices')
class IPFabricToNetboxDevicesFilter(DiffCollectionsFilter):
    fields = set(DeviceCollection.FIELDS) - {'model', 'ipaddr'}
    key_fields = ('hostname', )
