'use strict'
const util = require('util')
const npmlog = require('npmlog')
const Koa = require('koa')
const KoaBody = require('koa-body')
const getRawBody = require('raw-body')
const Sequelize = require('sequelize')
const axios = require('axios')

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
	logging: npmlog.verbose,
	operatorsAliases: false,
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

const body_normal = KoaBody({
    multipart: true
})

const body_raw = async (ctx,next) =>{
    ctx.request.body = await getRawBody(ctx.req,{
	limit: '40kb',
    })
    await next()
}

const rePathCheck = new RegExp("^/webpushtokencheck$")
const rePathCallback = new RegExp("^/webpushcallback/([^/\\?#]+)/([^/\\?#]+)")

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
	const row = rows[0]
	npmlog.info(`row tokenDigest=${row.tokenDigest}, installId=${row.installId}, updateAt=${row.updatedAt}`)
	if( install_id != row.installId ){
	    ctx.status=403
	    ctx.message=`installId not match.`
	    
	}else{
	    await row.update({ updatedAt: Sequelize.NOW })
	    npmlog.info(`row updated. ${row.updatedAt}`)
	    ctx.status = 200
	}
    })
}

async function pushCallback(ctx,m){
    return await body_raw(ctx,async()=>{

	try{
	    const device_id = decodeURIComponent(m[1])
	    const acct = decodeURIComponent(m[2])
	    const body = ctx.request.body
	    npmlog.info(`callback device_id=${device_id},acct=${acct},body=${body.length}bytes`)
	    
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
	    
	}catch(error){
	    npmlog.error( `sendToFCM failed. status: ${error.response.status}: ${JSON.stringify(error.response.data)}`)
	    ctx.status=500
	}
    })
}

async function handleRequest(ctx,next){
    const method = ctx.request.method
    const path = ctx.request.path
    npmlog.info(`${method} ${path}`)

    if( method=='POST' ){
	let m = rePathCheck.exec(path)
	if( m ) return await tokenCheck(ctx,m)

	m = rePathCallback.exec(path)
	if(m) return await pushCallback(ctx,m)
    }

    ctx.throw(404,'Not found') 
}

async function accessLog(ctx,next){
    try{
	await next()
    }finally{
	console.log(`${ctx.host} ${ctx.request.method} ${ctx.request.path} => ${ctx.status} ${ctx.message}`)
    }
}

async function main(){
    npmlog.info(`DB sync...`)
    await WebPushTokenCheck.sync()

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
