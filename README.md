使用移远EC20 4G模块自动发送短信获取闪讯密码

PS：闪讯现在无法固定密码，找营业厅，打10000投诉都没用，于是只能通使用EC 20 4G模块的AT指令发送短信获取闪讯密码并定时更新


设备：移远EC20 4G模块（本想用合宙Air780E，奈何不支持电信收发短信）

运行：

```
screen -dmS net_keeper python3 sms_pdu.py
```

获取密码：

```
curl http://127.0.0.1:8080/get_password
```