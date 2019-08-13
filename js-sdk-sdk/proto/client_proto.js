'use strict';

const crypto = require('crypto');
const xxhash = require('xxhashjs');

const ClientProto = function () {
    this.CreateTxRequest = function (prikey, pubkey, msg_id, from, to, amount) {
        var ProtoBufJs = require("protobufjs");
        var root = ProtoBufJs.loadSync("./proto/client.proto");
        var Header = root.lookupType("lego.client.protobuf.Header");
        var msg = Header.create();

        var dht_key_obj = crypto.createHash('sha256');
        dht_key_obj.update(prikey);
        msg.src_dht_key = dht_key_obj.digest('hex');
        msg.priority = 5;
        msg.id = msg_id;
        msg.type = 4;
        msg.client = false;
        msg.hop_count = 0;

        var BroadcastParam = root.lookupType('lego.client.protobuf.BroadcastParam');
        var broad_param = BroadcastParam.create();
        broad_param.layer_left = 0;
        broad_param.layer_right = "18446744073709551615";
        broad_param.ign_bloomfilter_hop = 1;
        broad_param.stop_times = 2;
        broad_param.hop_limit = 5;
        broad_param.hop_to_layer = 2;
        broad_param.neighbor_count = 7;
        msg.broadcast = broad_param;

        var BftMessage = root.lookupType('lego.client.protobuf.BftMessage');
        var bft_msg = BftMessage.create();
        var rand_str = this.uuid() + this.RandomString(1024);
        var gid_obj = crypto.createHash('sha256');
        gid_obj.update(rand_str);
        bft_msg.gid = gid_obj.digest('hex');
        bft_msg.rand = 0;
        bft_msg.status = 0;
        bft_msg.leader = false;
        bft_msg.net_id = 4;
        bft_msg.node_id = msg.src_dht_key;
        bft_msg.pubkey = pubkey;
        bft_msg.bft_address = "Transaction";

        var TxBft = root.lookupType('lego.client.protobuf.TxBft');
        var tx_bft = TxBft.create();
        tx_bft.gid = bft_msg.gid;
        tx_bft.from_acc_addr = from;
        tx_bft.from_pubkey = pubkey;
        tx_bft.tto_acc_addr = to;
        tx_bft.lego_count = amount;

        bft_msg.data = TxBft.encode(tx_bft).finish();
        var hash64 = this.XXHash64(bft_msg.data);
        var hash_hex = hash64.toString(16);
        var EC = require('elliptic').ec;
        var ec = new EC('secp256k1');
        var key = ec.keyFromPrivate(prikey);
        var signature = key.sign(hash_hex);
        var der_sign = signature.toDER();
        console.log(key.verify(hash_hex, der_sign));
        bft_msg.sign_challenge = signature.r.toString('hex');
        bft_msg.sign_response = signature.s.toString('hex');

        msg.data = BftMessage.encode(bft_msg).finish();
        return Header.encode(msg).finish();
    }

    this.uuid = function () {
        var s = [];
        var hexDigits = "0123456789abcdef";
        for (var i = 0; i < 36; i++) {
            s[i] = hexDigits.substr(Math.floor(Math.random() * 0x10), 1);
        }
        s[14] = "4";
        s[19] = hexDigits.substr((s[19] & 0x3) | 0x8, 1);
        s[8] = s[13] = s[18] = s[23] = "-";

        var uuid_str = s.join("");
        return uuid_str;
    }

    this.RandomString = function (len) {
        len = len || 32;
        var $chars = 'ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz0123456782';
        var maxPos = $chars.length;
        var pwd = '';
        for (var i = 0; i < len; i++) {
            pwd += $chars.charAt(Math.floor(Math.random() * maxPos));
        }
        return pwd;
    }

    this.XXHash64 = function (str) {
        var h = xxhash.h64();
        h.init(23456785675590);
        h.update(str);
        return h.digest();
    }
};

module.exports.ClientProto = ClientProto;