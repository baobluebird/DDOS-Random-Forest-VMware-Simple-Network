from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub

import switchm
from datetime import datetime

import pandas as pd
import joblib

class SimpleMonitor13(switchm.SimpleSwitch13):

    def __init__(self, *args, **kwargs):
        super(SimpleMonitor13, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)

        start = datetime.now()

        self.flow_model = joblib.load('Random_Forest.pkl')

        end = datetime.now()
        print("Model loading time: ", (end-start))

        self.flow_data = []  

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

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(10)

            self.flow_predict()

    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        timestamp = datetime.now().timestamp()


        self.flow_data = []
        body = ev.msg.body
        icmp_code = -1
        icmp_type = -1
        tp_src = 0
        tp_dst = 0

        for stat in sorted([flow for flow in body if (flow.priority == 1)], key=lambda flow:
            (flow.match['eth_type'], flow.match['ipv4_src'], flow.match['ipv4_dst'], flow.match['ip_proto'])):

            ip_src = stat.match['ipv4_src']
            ip_dst = stat.match['ipv4_dst']
            ip_proto = stat.match['ip_proto']

            if stat.match['ip_proto'] == 1:
                icmp_code = stat.match['icmpv4_code']
                icmp_type = stat.match['icmpv4_type']

            elif stat.match['ip_proto'] == 6:
                tp_src = stat.match['tcp_src']
                tp_dst = stat.match['tcp_dst']

            elif stat.match['ip_proto'] == 17:
                tp_src = stat.match['udp_src']
                tp_dst = stat.match['udp_dst']

            flow_id = str(ip_src) + str(tp_src) + str(ip_dst) + str(tp_dst) + str(ip_proto)

            try:
                packet_count_per_second = stat.packet_count / stat.duration_sec
                packet_count_per_nsecond = stat.packet_count / stat.duration_nsec
            except ZeroDivisionError:
                packet_count_per_second = 0
                packet_count_per_nsecond = 0

            try:
                byte_count_per_second = stat.byte_count / stat.duration_sec
                byte_count_per_nsecond = stat.byte_count / stat.duration_nsec
            except ZeroDivisionError:
                byte_count_per_second = 0
                byte_count_per_nsecond = 0

            self.flow_data.append([ev.msg.datapath.id, flow_id, ip_src, tp_src, ip_dst, tp_dst,
                                   stat.match['ip_proto'], icmp_code, icmp_type,
                                   stat.duration_sec, stat.duration_nsec,
                                   stat.packet_count, stat.byte_count,
                                   packet_count_per_second, packet_count_per_nsecond,
                                   byte_count_per_second, byte_count_per_nsecond])

    def flow_predict(self):
        try:
            if not self.flow_data:
                return

            predict_flow_df = pd.DataFrame(self.flow_data, columns=[
                'datapath_id', 'flow_id', 'ip_src', 'tp_src', 'ip_dst', 'tp_dst',
                'ip_proto', 'icmp_code', 'icmp_type',
                'flow_duration_sec', 'flow_duration_nsec',
                'packet_count', 'byte_count',
                'packet_count_per_second', 'packet_count_per_nsecond',
                'byte_count_per_second', 'byte_count_per_nsecond'])

            selected_features = ['flow_duration_sec', 'packet_count', 'byte_count',
                                 'packet_count_per_second', 'byte_count_per_second',
                                 'ip_proto', 'icmp_code', 'icmp_type']
            X_predict_flow = predict_flow_df[selected_features].values
            X_predict_flow = X_predict_flow.astype('float64')

            y_flow_pred = self.flow_model.predict(X_predict_flow)

            legitimate_traffic = 0
            ddos_traffic = 0
            victim = None

            for i, pred in enumerate(y_flow_pred):
                if pred == 0:
                    legitimate_traffic += 1
                else:
                    ddos_traffic += 1
                    victim_ip = predict_flow_df.iloc[i, 4]  
                    victim = self._determine_host(victim_ip)

            self.logger.info("------------------------------------------------------------------------------")
            if (legitimate_traffic / len(y_flow_pred) * 100) > 1:
                self.logger.info("Traffic is Legitimate!")
            else:
                self.logger.info("NOTICE!! DoS Attack in Progress!!!")
                if victim:
                    self.logger.info(f"Victim Host: {victim}")
                else:
                    self.logger.info("Victim Host: Unknown")
                print("Mitigation process in progress!")
                self.mitigation = 1

            self.logger.info("------------------------------------------------------------------------------")

        except Exception as e:
            self.logger.error(f"Error during prediction: {str(e)}")

    def _determine_host(self, victim_ip):
        ip_to_host_mapping = {
            '10.0.0.1': 'h1',
            '10.0.0.2': 'h2',
            '10.0.0.3': 'h3',
            '10.0.0.4': 'h4',
            '10.0.0.5': 'h5',
            '10.0.0.6': 'h6',
            '10.0.0.7': 'h7',
            '10.0.0.8': 'h8',
            '10.0.0.9': 'h9',
            '10.0.0.10': 'h10',
            '10.0.0.11': 'h11',
            '10.0.0.12': 'h12',
            '10.0.0.13': 'h13',
            '10.0.0.14': 'h14',
            '10.0.0.15': 'h15',
            '10.0.0.16': 'h16',
            '10.0.0.17': 'h17',
            '10.0.0.18': 'h18',
        }
        return ip_to_host_mapping.get(victim_ip, 'Unknown host')

if __name__ == "__main__":
    from ryu.base import app_manager
    app_manager.run_apps([SimpleMonitor13])

