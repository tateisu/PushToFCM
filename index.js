'use strict'
const util = require('util')
const crypto = require('crypto')
const npmlog = require('npmlog')
const Koa = require('koa')
const KoaBody = require('koa-body')
const getRawBody = require('raw-body')
const Sequelize = require('sequelize')
const axios = require('axios')
const base64us = require('urlsafe-base64')
const asn = require('asn1.js')
const jwt = require('jsonwebtoken')

const fcmServerKey = process.env.FCM_SERVER_KEY
if(! fcmServerKey) throw new Error("missing FCM_SERVER_KEY in .env")

process.on('unhandledRejection', console.dir);

npmlog.info(`database: ${process.env.DB_DIALECT} ${process.env.DB_HOST} ${process.env.DB_PORT} ${process.env.DB_NAME} ${process.env.DB_USER}`)

const sequelize = new Sequelize(
    process.env.DB_NAME,
    process.env.DB_USER,
    process.env.DB_PASS,
    {
	dialect: process.env.DB_DIALECT,
	host: process.env.DB_HOST,
	port: process.env.DB_PORT,
	operatorsAliases: false,

	logging: (a,b,c,file,dir)=>{
	    //const args = Array.from(arguments)
	    //npmlog.info(`logging ${dir} ${file}`)

	    //npmlog.info(`SQL Log: ${a}` )
	}
    }
)

const WebPushTokenCheck = sequelize.define('webpush_token_check', {

    id: {
	type: Sequelize.INTEGER,
	primaryKey: true,
	autoIncrement: true,
    },
    
    tokenDigest: {
	type: Sequelize.STRING,
	allowNull: false,
    },

    installId: {
	type: Sequelize.STRING,
	allowNull: false,
    },

    createdAt: {
	type: Sequelize.DATE,
	defaultValue: Sequelize.NOW,
	allowNull: false,
    },

    updatedAt: {
	type: Sequelize.DATE,
	defaultValue: Sequelize.NOW,
	allowNull: false,
    },
}, {
    indexes: [
	{
		name: 'webpush_token_check_token',
		unique: true,
		fields: ['tokenDigest']
	}
    ]
})

const ServerKey = sequelize.define('webpush_server_key2', {
    clientId: {
	type: Sequelize.STRING,
	allowNull: false,
    },

    serverKey: {
	type: Sequelize.STRING,
	allowNull: false,
    },
},{
    indexes: [
	{
	    name: 'webpush_server_key2_unique',
	    unique: true,
	    fields: ['clientId']
	}
    ]
})

const body_normal = KoaBody({
    multipart: true
})

const body_raw = async (ctx,next) =>{
    ctx.request.body = await getRawBody(ctx.req,{
	limit: '40kb',
    })
    await next()
}

async function serverKeyUpdate(ctx,m){
    return await body_normal(ctx,async()=>{

	const client_id = ctx.request.body.client_id
	const server_key = ctx.request.body.server_key

	npmlog.info(`serverKeyUpdate client_id=${client_id}, server_key=${server_key}`)

	if( !client_id) ctx.throw(422,`missing parameter 'client_id'`)
	if( !server_key ) ctx.throw(422,`missing parameter 'server_key'`)

	const created = await ServerKey.upsert({
	    clientId: client_id,
	    serverKey: server_key
	})
	npmlog.info(`created=${created}`)

	ctx.status = 200
    })
}

async function tokenCheck(ctx,m){
    return await body_normal(ctx,async()=>{
	const token_digest=ctx.request.body.token_digest
	const install_id=ctx.request.body.install_id
	npmlog.info(`check token_digest=${token_digest},install_id=${install_id}`)
	if( !token_digest ) ctx.throw(422,`missing parameter 'token_digest'`)
	if( !install_id ) ctx.throw(422,`missing parameter 'install_id'`)
	const rows = await WebPushTokenCheck.findOrCreate({
	    where: {
		tokenDigest: token_digest
	    },
	    defaults: {
		installId: install_id
	    }
	})
	if( rows == null || rows.length == 0 ){
	    ctx.throw(500,`findOrCreate() returns null or empty.`) 
	}
	let row = rows[0]
	npmlog.info(`row tokenDigest=${row.tokenDigest}, installId=${row.installId}, updatedAt=${row.updatedAt}`)
	if( install_id != row.installId ){
	    ctx.status=403
	    ctx.message=`installId not match.`
	}else{
	    const affected = await WebPushTokenCheck.update({
		updatedAt: sequelize.literal('CURRENT_TIMESTAMP')
	    },{
		where:{
		    id: row.id
		}
	    })
	    if( affected[0] != 1){
		npmlog.info(`row update? affected=${affected[0]}`)
	    }
	    ctx.status = 200
	}
    })
}

function decodeBase64(src){
    return new Buffer(src,'base64')
}

// ECDSA public key ASN.1 format
const ECPublicKey = asn.define("PublicKey", function() {
    this.seq().obj(
	this.key("algorithm").seq().obj(
	    this.key("id").objid(),
	    this.key("curve").objid()
	),
	this.key("pub").bitstr()
    );
});

// convert public key from p256ecdsa to PEM
function getPemFromPublicKey(public_key){
    return ECPublicKey.encode({
	algorithm: {
	    id: [1, 2, 840, 10045, 2, 1],  // :id-ecPublicKey
	    curve: [1,2,840,10045,3,1,7] // prime256v1
	},
	pub: {
	    // このunused により bitstringの先頭に 00 が置かれる。
	    // 先頭の00 04 が uncompressed を示す
	    // https://tools.ietf.org/html/rfc5480#section-2.3.2
	    // http://www.secg.org/sec1-v2.pdf section 2.3.3
	    unused: 0,
	    data: public_key,
	},
    }, "pem", {label: "PUBLIC KEY"})
}

const reAuthorizationWebPush = new RegExp("^WebPush\\s+(\\S+)")
const reCryptoKeySignPublicKey = new RegExp("p256ecdsa=([^;\\s]+)")


function verifyServerKey(ctx, savedServerKey){
    const auth_header = ctx.get('Authorization')
    const crypto_key = ctx.get('Crypto-Key')
    if( auth_header && crypto_key ){
	let m = reAuthorizationWebPush.exec( auth_header )
	if( !m ){
	    console.log("header not match: Authorization")
	}else{
	    const token = m[1]

	    m = reCryptoKeySignPublicKey.exec(crypto_key)
	    if( !m ){
		console.log("header not match: Crypto-Key")
	    }else{
		const public_key = decodeBase64(m[1])
		const saved_key = decodeBase64(savedServerKey)
		if( 0 != Buffer.compare( public_key, saved_key) ){
		    ctx.throw(400,"server_key not match.")
		}
		
		const pem = getPemFromPublicKey(public_key)
		try{
		    jwt.verify(token, Buffer.from(pem), { algorithms: ['ES256'] })
		    return true
		}catch(err){
		    ctx.throw(503,`JWT verify failed. ${err}`)
		}
	    }
	}
    }
    ctx.throw(400,"missing JWT signature.")
    return false
}

async function pushCallback(ctx,m){
    return await body_raw(ctx,async()=>{

	const params = m[1].split('/').map( x => decodeURIComponent(x) )
	const device_id = params[0]
	const acct = params[1]
	const flags = params[2] // may null, not used
	const client_id = params[3] // may null
	
	const body = ctx.request.body
	npmlog.info(`callback device_id=${device_id},acct=${acct},body=${body.length}bytes`)
	
	if( client_id ){
	    const row = await ServerKey.findOne({
		where:{
		    clientId: client_id
		}
	    })
	    if( row == null ){
		npmlog.info(`missing serverkey for client_id=${client_id}`)
	    }else{
		if(!verifyServerKey(ctx, row.serverKey)){
		    npmlog.error("verifyServerKey failed.")
		    return
		}
	    }
	}

	try{
	    const firebaseMessage = {
		to: device_id,
		priority: 'high',
		data: {
		    acct: acct,
		}
	    }

	    const response = await axios.post(
		'https://fcm.googleapis.com/fcm/send',
		JSON.stringify(firebaseMessage),
		{
		    headers: {
			'Authorization': `key=${fcmServerKey}`,
			'Content-Type': 'application/json'
		    }
		}
	    )
    
	    npmlog.info(`sendToFCM: status=${response.status} ${JSON.stringify(response.data)}`)

	    if (response.data.failure === 0 && response.data.canonical_ids === 0) {
		ctx.status = 201
		return
	    }

	    response.data.results.forEach(result => {
		if (result.message_id && result.registration_id) {
		    // デバイストークンが更新された
		    // この購読はキャンセルされるべき
		    ctx.status = 410
		}else if( result.error == 'NotRegistered' ){
		    ctx.status = 410
		}else{
		    npmlog.error(`sendToFCM error response. ${result.error}`)
		    ctx.status = 502
		}
	    })
	}catch(err){
	    if( err.response ){
		ctx.throw( 503, `sendToFCM failed. status: ${err.response.status}: ${JSON.stringify(err.response.data)}`)
	    }else{
		ctx.throw( 503, `sendToFCM failed. ${err}`)
	    }
	}
    })
}

const rePathCheck = new RegExp("^/webpushtokencheck$")
const rePathCallback = new RegExp("^/webpushcallback/([^\\?#]+)")
const rePathServerKey = new RegExp("/webpushserverkey$")

async function handleRequest(ctx,next){
    const method = ctx.request.method
    const path = ctx.request.path
    npmlog.info(`${method} ${path}`)

    if( method=='POST' ){
	let m = rePathCheck.exec(path)
	if( m ) return await tokenCheck(ctx,m)

	m = rePathCallback.exec(path)
	if( m ) return await pushCallback(ctx,m)

	m = rePathServerKey.exec(path)
	if( m ) return await serverKeyUpdate(ctx,m)

    }
    npmlog.info("status=${ctx.status}")
    ctx.throw(404,'Not found') 
}

function accessLog_sub(ctx,err){
    const status = err ? ( err.status || 500) : (ctx.status || 404)
    const message = err ? (err.message || '(no error message)') : (ctx.message || '(no message)')
    console.log(`${ctx.host} ${ctx.request.method} ${ctx.request.path} => ${status} ${message}`)
}

async function accessLog(ctx,next){
    try{
	await next()
    }catch(err){
	accessLog_sub(ctx,err)
	throw err
    }
    accessLog_sub(ctx)
}

async function main(){
    npmlog.info(`DB sync...`)
    await WebPushTokenCheck.sync()
    await ServerKey.sync()

    const app = new Koa()
    app.use(accessLog)
    app.use(handleRequest)

    const port = process.env.LISTEN_PORT || 4005
    const addr = process.env.LISTEN_ADDR || '127.0.0.1'
    app.listen(port,addr,()=>{
	npmlog.info(`listening on addr ${addr} port ${port}...`)
    })
}

main()
