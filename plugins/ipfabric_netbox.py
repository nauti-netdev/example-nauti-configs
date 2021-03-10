from nauti.collections.devices import DeviceCollection
from nauti.auditor import Auditor
from nauti.tasks.reconile import Reconciler
from nauti.collection import get_collection
from nauti_ipfabric_netbox.devices import IPFabricNetboxDeviceCollectionReconciler


@Reconciler.register('ipfabric', 'netbox', 'devices')
class ReconcileIPFabricToNetboxDevices(IPFabricNetboxDeviceCollectionReconciler):

    async def update_items(self):
        # need to build the IPaddrs cache for the device update function to work properly
        # TODO: review this approach
        col_ipaddrs = get_collection(self.target.source, 'ipaddrs')
        items = {
            hostname: self.target.items[hostname]
            for hostname in self.diff_res.changes
        }

        await col_ipaddrs.fetch_items(items=items)
        col_ipaddrs.make_keys()
        self.target.cache['ipaddrs'] = col_ipaddrs
        await super().update_items()


@Auditor.register('ipfabric', 'netbox', 'devices')
class AuditIPFabricToNetboxDevices(Auditor):
    fields = set(DeviceCollection.FIELDS) - {'model'}
    key_fields = ('hostname', )

    def origin_key_filter(self, item: dict):
        # ignore Meraki, Cisco APs and Palo FW devices
        if item['os_name'] in ['lap', 'pan-os', 'meraki']:
            return False

        return True

    def target_key_filter(self, item: dict):
        """ only include items that are present in the origin source """
        return item['hostname'] in self.origin.items


@Auditor.register(
    name='mlb-radio', collection='devices',
    origin='ipfabric', target='netbox'
)
class AuditIPFabricToNetboxMLBRadioDevices(Auditor):
    fields = set(DeviceCollection.FIELDS)
    key_fields = ('hostname', )

    def origin_fetch_filter(self):
        return 'siteName = MLB-Radio'

    def origin_key_filter(self, item):
        item['site'] = item['site'].lower()
        return True

    def target_key_filter(self, item: dict):
        """ only include items that are present in the origin source """
        return item['hostname'] in self.origin.items
