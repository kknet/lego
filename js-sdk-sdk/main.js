'use strict';
const axios = require('axios');
const { ClientProto } = require("./proto/client_proto");
let client_proto = new ClientProto();
const { HttpRequest } = require("./proto/http_req");
let http_request = new HttpRequest();

var EC = require('elliptic').ec;
var ec = new EC('secp256k1');
var key = ec.genKeyPair();

var msg = client_proto.CreateTxRequest(
    key.getPrivate().toString('hex'),
    key.getPublic().encode('hex'),
    1, 'from', 'to', 10);
console.log(msg);

var res = http_request.SendRequest('192.168.20.17', '8080', msg);
console.log(res);

return;


var ProtoBufJs = require("protobufjs");
var root = ProtoBufJs.loadSync("./proto/client.proto");
var BftMessage = root.lookupType("lego.client.protobuf.BftMessage");
var bft_msg = BftMessage.create();
bft_msg.gid = "gid";
bft_msg.rand = 0;
var buffer = BftMessage.encode(bft_msg).finish();
let data = { "note": "1234", "name": "yyyy" };
axios.post('http://192.168.20.17:8080/person', data)
    .then(res => {
        console.log('res=>', res);
    })
return;
axios({
    method: 'post',
    url: 'http://192.168.20.17:8080/person',
    data: {
        'name': 'john',
        'note': 'coder'
    },
}).then(function (response) {
    console.log(response.data);
  });

const {TransMode,TransBase} = require("./rpc/trans_base");
let {GLOBAL,g_user_info} = require("./model/global_defination");
const {APIMethodImpl} = require("./impl/api_method_impl");
const {http_handler_instance} = require("./rpc/http_handler");
const {StringUtil} = require('./base/string_util');
//const ByteBuffer = require('ByteBuffer');
const ByteBuffer = require('ByteBuffer');
const secp256k1 = require('secp256k1');
const {randomBytes} = require('crypto');
const  {Ecdsa} = require('./base/ecdsa');
const {sha256} = require('js-sha256');
const bitcoin = require('@trezor/utxo-lib');

const DEFAULT_ACCOUNT = GLOBAL.ACCONT_ONE;
let g_server_host_port = "";

const change_trans_mode = function (use_http) {
    if(true === use_http) {
        g_server_host_port = GLOBAL.SERVER_HOST_PORT_HTTP;
        TransBase.s_default_mode = TransMode.HTTP;
    } else {
        g_server_host_port = GLOBAL.SERVER_HOST_PORT_WS;
        TransBase.s_default_mode = TransMode.WS;
    }
};

const make_private_key = function () {
    console.log(g_user_info);
    let private_key_wrap = {key:""};
    let address_wrap = {address:""};
    let local_storage = window.localStorage;
    let item = local_storage.getItem("top_private_key");
    if(item != null) {
        let item_bytes = StringUtil.hex2bytes(item);
        g_user_info.set_private_key(item_bytes);
    } else {
        api_method_impl.make_private_key(private_key_wrap,address_wrap);
        g_user_info.set_private_key(private_key_wrap.key);
        let hex_key = StringUtil.bytes2hex(private_key_wrap.key);
        local_storage.setItem("top_private_key",hex_key);
    }
};

const make_address = function() {
    let pri_key = g_user_info.get_private_key();
    const private_key_buffer = Buffer.from(pri_key);
    const pub_key = secp256k1.publicKeyCreate(private_key_buffer,false);
    const hash =  bitcoin.crypto.sha256(pub_key);
    const ripemd = bitcoin.crypto.ripemd160(hash);
    const address = bitcoin.address.toBase58Check(ripemd,0);
    const account_addr = "T-0-" + address;
    g_user_info.set_account(account_addr);
};
http_handler_instance.init();
change_trans_mode(true);
let api_method_impl = new APIMethodImpl();
make_private_key();
make_address();
window.request_token = function () {
    console.log(g_user_info);
    api_method_impl.request_token(g_user_info);
};

window.create_account = function () {
    console.log(g_user_info);
    api_method_impl.create_account(g_user_info);
};

window.make_private_key = function () {
    make_private_key();
};

window.get_property = function () {
    const type = "list";
    const data1 = "param1";
    const data2 = "param2";
    api_method_impl.get_property(g_user_info,type,data1,data2);
};

window.transfer = function () {
    const from_account = g_user_info.get_account();
    const to_account = "T-0-1EHzT2ejd12uJx7BkDgkA7B5DS1nM6AXyF";
    //const to_account = "T-0-1EHzT2ejd12uJx7BkDgkA7B5F";
    api_method_impl.transfer(g_user_info,from_account,to_account,10);
};

window.account_info = function () {
    api_method_impl.account_info(g_user_info);
};

window.key_store = function () {
    const type = document.getElementById("key").value;
    const value = document.getElementById("value").value;
    console.log("type:{0},value:{1}".format(type,value));
    api_method_impl.key_store(g_user_info,type,value);
};
