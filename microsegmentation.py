from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import dpid as dpid_lib
from ryu.lib import stplib
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ethernet
import ryu.app.ofctl.api as api
from ryu.lib.packet import in_proto
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.app.wsgi import WSGIApplication, ControllerBase, route
from webob import Response
from ryu.lib import hub


risk_manager_instance_name = 'risk_manager_api_app'
url = '/riskLevel'


class MyFirstApp(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'stplib': stplib.Stp, 'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(MyFirstApp, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.src_dict = {}
        wsgi = kwargs['wsgi']
        wsgi.register(RiskWebApi,
                      {risk_manager_instance_name: self})


        self.stp = kwargs['stplib']

        # Sample of stplib config.
        #  please refer to stplib.Stp.set_config() for details.
        config = {dpid_lib.str_to_dpid('0000000000000001'):
                  {'bridge': {'priority': 0x8000}},
                  dpid_lib.str_to_dpid('0000000000000002'):
                  {'bridge': {'priority': 0x9000}},
                  dpid_lib.str_to_dpid('0000000000000003'):
                  {'bridge': {'priority': 0xa000}}}
        self.stp.set_config(config)

        #Conmutadores de la red
        self.datapaths = {}
        #Nivel de riesgo 
        self.riskLevel = 0
        #Hebra monitora del nivel de riesgo
        self.riskLevel_thread = hub.spawn(self._riskLevelMonitor)
        #Conmutadores en los que instalar las reglas de microsegmentacion
        self.dpDrop = {1,4}
        #Direcciones IP de los sistemas finales criticos
        self.ipsToProtect = {"195.0.0.1", "195.0.0.5"}
        #Direcciones IP del resto de sistemas finales
        self.ipsToBlock = {"195.0.0.2", "195.0.0.3", "195.0.0.4", "195.0.0.6", "195.0.0.7", "195.0.0.8"}
        #Variable que indica si se ha realizado la microsegmentacion de nivel medio
        self.times = 0
        #Variable que indica si se ha realizado la microsegmentacion de nivel alto
        self.times2 = 0


    #Metodo para modificar el valor del nivel de riesgo 
    def set_riskLevel(self, value):
        
        self.riskLevel = value
        return self.riskLevel


    #Hebra monitora del nivel de riesgo, indica la acción a realizar
    def _riskLevelMonitor(self):
        while True:
            if self.riskLevel == 0:
                if (self.times == 1 and self.times2 == 1) :
                    self._undo()
                    self._undo2()
                elif self.times == 1:
                    self._undo()
                elif self.times2 == 1:
                    self._undo2()
            elif (self.riskLevel == 1 and self.times == 0):
                self._microsegmentate()
                if self.times2 == 1:
                    self._undo2()
            elif (self.riskLevel == 1 and self.times == 1 and self.times2 == 1):
                self._undo2()
            elif (self.riskLevel == 2 and self.times2 == 0):
                self._microsegmentate2()
            hub.sleep(10)

    #Metodo para deshacer la microsegmentacion de nivel medio   
    def _undo(self):

        if not self.datapaths:
            return

        self.logger.info("Risk level back to 0, undo microsegmentation of ports")

        for d in self.dpDrop:

            self.logger.info("Deleting rules of switch%d", d)

            ofproto = self.datapaths[d].ofproto
            parser = self.datapaths[d].ofproto_parser

            msg = parser.OFPFlowMod(datapath=self.datapaths[d], cookie=1, cookie_mask= 0xFFFFFFFFFFFFFFFF,
                                    table_id= ofproto.OFPTT_ALL, command= ofproto.OFPFC_DELETE,
                                    out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY)

            self.datapaths[d].send_msg(msg)

        self.times = 0

    
    #Metodo para deshacer la microsegmentacion de nivel alto
    def _undo2(self):

        if not self.datapaths:
            return

        self.logger.info("Risk level back to 0 or 1, undo full microsegmentation")

        for d in self.dpDrop:

            self.logger.info("Deleting rules of switch%d", d)

            ofproto = self.datapaths[d].ofproto
            parser = self.datapaths[d].ofproto_parser

            
            msg = parser.OFPFlowMod(datapath=self.datapaths[d], cookie=2, cookie_mask= 0xFFFFFFFFFFFFFFFF,
                        table_id= ofproto.OFPTT_ALL, command= ofproto.OFPFC_DELETE,
                        out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY)



            self.datapaths[d].send_msg(msg)

        self.times2 = 0

    
    #Metodo para realizar la microsegmentacion de nivel medio
    def _microsegmentate(self):

        #Antes de realizar la microsegmentacion el controlador debe haber identificado los conmutadores de la red 
        if not self.datapaths:
            return

        self.logger.info("Risk level 1, start microsegmentation of ports")

        
        #Se ejecuta el bucle para los conmutadores en los que instalar las reglas de microsegmentacion
        for d in self.dpDrop:

            ofproto = self.datapaths[d].ofproto
            parser = self.datapaths[d].ofproto_parser

            self.logger.info("Adding rules to switch%d", d)

            for ip in self.ipsToProtect:

                for ip2 in self.ipsToBlock:

                    #Microsegmentacion por puertos, protegiendo el acceso los puertos 5001 y 8080 de los sistemas finales criticos desde el exterior del microsegmento
                    match1 = parser.OFPMatch(eth_type=0x800, ip_proto=6, ipv4_src=ip2, ipv4_dst=ip, tcp_dst=5001)
                    match2 = parser.OFPMatch(eth_type=0x800, ip_proto=6, ipv4_src=ip2, ipv4_dst=ip, tcp_dst=8080)
                    instruction = [parser.OFPInstructionActions(ofproto.OFPIT_CLEAR_ACTIONS, [])]

                    msg1 = parser.OFPFlowMod(datapath=self.datapaths[d], priority=2, cookie = 1,
                                            match=match1, instructions=instruction)
                    msg2 = parser.OFPFlowMod(datapath=self.datapaths[d], priority=2, cookie = 1,
                                            match=match2, instructions=instruction)

                    self.datapaths[d].send_msg(msg1)
                    self.datapaths[d].send_msg(msg2)

        self.times = 1

    #Metodo para realizar la microsegmentacion de nivel alto
    def _microsegmentate2(self):


        if not self.datapaths:
            return

        self.logger.info("Risk level 2, start full microsegmentation")

        #Se ejecuta el bucle para los conmutadores en los que instalar las reglas de microsegmentacion
        for d in self.dpDrop:

            self.logger.info("Adding rules to switch%d", d)

            ofproto = self.datapaths[d].ofproto
            parser = self.datapaths[d].ofproto_parser

            for ip in self.ipsToBlock:
                
                self.logger.info("Blocking address " + ip + " for switch%d", d)

                #Microsegmentacion completa, protegiendo acceso a los sistemas finales criticos desde el exterior del microsegmento
                match = parser.OFPMatch(eth_type=0x800, ipv4_src= ip)
                instruction = [parser.OFPInstructionActions(ofproto.OFPIT_CLEAR_ACTIONS, [])]

                msg = parser.OFPFlowMod(datapath=self.datapaths[d], priority=2, cookie = 2,
                                        match=match, instructions=instruction)

                self.datapaths[d].send_msg(msg)

        self.times2 = 1


    #Los siguientes metodos provienen de la documentacion de ryu. En ellos se implementa el forwarding dinamico y el algoritmo STP.

    def delete_flow(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        for dst in self.mac_to_port[datapath.id].keys():
            match = parser.OFPMatch(eth_dst=dst)
            mod = parser.OFPFlowMod(
                datapath, command=ofproto.OFPFC_DELETE,
                out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
                priority=1, match=match)
            datapath.send_msg(mod)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.logger.info("Adding flow to switch%d", datapath.id)

        # construct flow_mod message and send it.
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                                actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)
        ##############################################################################################
        # This section is needed to guarantee that each rule is installed in order.
        # Otherwise, there are problems in which a packet goes back to the controller because the
        # rule in the next switch has still to be implemented.
        # We send a barrier request that forces the switch to install it immediately before processing
        # another packet.
        # Fixed in OpenFlow 1.4 with BundleMsg
        msg = parser.OFPBarrierRequest(datapath)
        api.send_msg(self, msg, reply_cls=datapath.ofproto_parser.OFPBarrierReply, reply_multi=True)
        ##############################################################################################



    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install the table-miss flow entry.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self.logger.info("Table miss installed for switch: %s", datapath.id)



    @set_ev_cls(stplib.EventPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        self.logger.info("out_port is %s", out_port)
        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)


    @set_ev_cls(stplib.EventTopologyChange, MAIN_DISPATCHER)
    def _topology_change_handler(self, ev):
        dp = ev.dp
        dpid_str = dpid_lib.dpid_to_str(dp.id)
        msg = 'Receive topology change event. Flush MAC table.'
        self.logger.debug("[dpid=%s] %s", dpid_str, msg)

        if dp.id in self.mac_to_port:
            self.delete_flow(dp)
            del self.mac_to_port[dp.id]

    @set_ev_cls(stplib.EventPortStateChange, MAIN_DISPATCHER)
    def _port_state_change_handler(self, ev):
        dpid_str = dpid_lib.dpid_to_str(ev.dp.id)
        of_state = {stplib.PORT_STATE_DISABLE: 'DISABLE',
                    stplib.PORT_STATE_BLOCK: 'BLOCK',
                    stplib.PORT_STATE_LISTEN: 'LISTEN',
                    stplib.PORT_STATE_LEARN: 'LEARN',
                    stplib.PORT_STATE_FORWARD: 'FORWARD'}
        self.logger.debug("[dpid=%s][port=%d] state=%s",
                          dpid_str, ev.port_no, of_state[ev.port_state])


    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]


#En esta clase se implementa la API REST para la comunicacion con el controlador

class RiskWebApi(ControllerBase):

    def __init__(self, req, link, data, **config):
        super(RiskWebApi, self).__init__(req, link, data, **config)
        self.risk_manager_app = data[risk_manager_instance_name]

    #Implementacion del endpoint GET /riskLevel, muestra el nivel de riesgo actual
    @route('riskLevel', url, methods=['GET'])
    def show_riskLevel(self, req, **kwargs):

        risk_manager = self.risk_manager_app
        body = str(risk_manager.riskLevel)


        return Response(content_type='text/plain', body=body)

    #Implementacion del endpoint PUT /riskLevel, modifica el nivel de riesgo con el valor incluido en el cuerpo de la peticion
    @route('riskLevel', url, methods=['PUT'])
    def set_riskLevel(self, req, **kwargs):

        risk_manager = self.risk_manager_app
        
        try:
            new_entry = req.json if req.body else {}
        except ValueError:
            raise Response(status=400)


        try:
            if new_entry not in [0, 1, 2]:
                return
            riskLevel = risk_manager.set_riskLevel(new_entry)
            body = str(riskLevel)
            return Response(content_type='text/plain', body=body)
        except Exception as e:
            return Response(status=500)
