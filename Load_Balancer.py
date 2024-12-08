from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, arp
from ryu.lib.packet import ether_types
from collections import defaultdict

class LoadBalancer(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(LoadBalancer, self).__init__(*args, **kwargs)
        # Daftar server backend
        self.server_pool = ['10.0.0.2', '10.0.0.3', '10.0.0.4']
        self.server_index = 0
        self.mac_to_port = defaultdict(dict)
        self.ip_to_mac = {}

    def select_server(self):
        # Round-robin load balancing
        server = self.server_pool[self.server_index]
        self.server_index = (self.server_index + 1) % len(self.server_pool)
        return server

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        # Skip packets not related to IPv4 or ARP
        if eth.ethertype not in [ether_types.ETH_TYPE_IP, ether_types.ETH_TYPE_ARP]:
            return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        self.mac_to_port[dpid][src] = in_port

        # Handle ARP Requests
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            self.ip_to_mac[arp_pkt.src_ip] = src
            if arp_pkt.dst_ip in self.server_pool:
                # Respond to ARP Request
                self.handle_arp(datapath, pkt, arp_pkt, in_port)
            return

        # Handle IPv4 packets
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt and ip_pkt.dst in self.server_pool:
            selected_server = self.select_server()
            self.redirect_to_server(datapath, pkt, selected_server, in_port)

    def handle_arp(self, datapath, pkt, arp_pkt, in_port):
        parser = datapath.ofproto_parser
        src_ip = arp_pkt.src_ip
        dst_ip = arp_pkt.dst_ip

        # ARP Reply
        if dst_ip in self.server_pool:
            selected_server = self.select_server()
            if selected_server in self.ip_to_mac:
                server_mac = self.ip_to_mac[selected_server]
                arp_reply = packet.Packet()
                arp_reply.add_protocol(ethernet.ethernet(
                    ethertype=pkt.get_protocols(ethernet.ethernet)[0].ethertype,
                    dst=pkt.get_protocols(ethernet.ethernet)[0].src,
                    src=server_mac
                ))
                arp_reply.add_protocol(arp.arp(
                    opcode=arp.ARP_REPLY,
                    src_mac=server_mac,
                    src_ip=selected_server,
                    dst_mac=pkt.get_protocols(ethernet.ethernet)[0].src,
                    dst_ip=src_ip
                ))
                arp_reply.serialize()
                actions = [parser.OFPActionOutput(in_port)]
                out = parser.OFPPacketOut(
                    datapath=datapath, buffer_id=datapath.ofproto.OFP_NO_BUFFER,
                    in_port=datapath.ofproto.OFPP_CONTROLLER,
                    actions=actions, data=arp_reply.data
                )
                datapath.send_msg(out)

    def redirect_to_server(self, datapath, pkt, server_ip, in_port):
        parser = datapath.ofproto_parser
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        ip = pkt.get_protocols(ipv4.ipv4)[0]

        if server_ip not in self.ip_to_mac:
            return

        server_mac = self.ip_to_mac[server_ip]

        # Install a flow rule
        match = parser.OFPMatch(eth_type=0x0800, ipv4_dst=ip.dst, in_port=in_port)
        actions = [parser.OFPActionSetField(ipv4_dst=server_ip),
                   parser.OFPActionSetField(eth_dst=server_mac),
                   parser.OFPActionOutput(port=self.mac_to_port[datapath.id][server_mac])]
        self.add_flow(datapath, 10, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)
