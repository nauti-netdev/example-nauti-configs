from nauti.collections.devices import DeviceCollection
from nauti.auditor import Auditor
from nauti_netbox.auditors import NetboxWithDeviceAuditor

@Auditor.register('netbox', 'clearpass', 'devices')
class Nb2CPDevicesAuditor(Auditor):
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


@Auditor.register('ipfabric', 'netbox', 'devices')
class AuditIPFabricToNetboxDevices(Auditor):
    fields = set(DeviceCollection.FIELDS) - {'model'}
    key_fields = ('hostname', )

    def origin_key_filter(self, item: dict):
        # ignore Cisco APs and Palo FW devices
        if item['os_name'] in ['lap', 'pan-os']:
            return False

        return True

    def target_key_filter(self, item: dict):
        """ only include items that are present in the origin source """
        return item['hostname'] in self.origin.items


# @DiffCollectionsFilter.register('ipfabric', 'netbox', 'devices')
# class IPFabricToNetboxDevicesFilter(DiffCollectionsFilter):
#     fields = set(DeviceCollection.FIELDS) - {'model', 'ipaddr'}
#     key_fields = ('hostname', )



