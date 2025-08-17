import os
from datetime import datetime
import json
import asyncio
import aiohttp
import configparser
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
from astrbot.api.event import filter, AstrMessageEvent
from astrbot.api.star import Context, Star, register

@register("astrbot_plugin_chatsummary_bark", "Battery-rar", "一个基于LLM的自动历史聊天记录总结插件", "1.0.0")
# 聊天记录总结插件主类，继承自Star基类
class ChatSummary_bark(Star):
    # 初始化插件实例
    def __init__(self, context: Context, config: dict):
        super().__init__(context)
        self.config = config
    # 注册指令的装饰器。
    @filter.event_message_type(filter.EventMessageType.GROUP_MESSAGE)  # 消息历史获取与处理
    async def summary(self, event: AstrMessageEvent):
        """触发消息总结"""
        from astrbot.core.platform.sources.aiocqhttp.aiocqhttp_message_event import AiocqhttpMessageEvent
        assert isinstance(event, AiocqhttpMessageEvent)
        client = event.bot
        # 构造获取群消息历史的请求参数
        payloads = {
          "group_id": event.get_group_id(),
          "message_seq": 0,
          "count": 1,
          "reverseOrder": False
        }
        

        # 调用API获取群聊历史消息
        ret = await client.api.call_action("get_group_msg_history", **payloads)

        myid_post = await client.api.call_action("get_login_info")
        myid = myid_post.get("user_id", {})

        # 处理消息历史记录，对其格式化
        messages = ret.get("messages", [])
        chat_lines = []
        for msg in messages:
            # 解析发送者信息
            sender = msg.get('sender', {})
            nickname = sender.get('nickname', '未知用户')
            if myid == sender.get('user_id', ""):
                continue
            msg_time = datetime.fromtimestamp(msg.get('time', 0))  # 防止time字段缺失
            # 提取所有文本内容（兼容多段多类型文本消息）
            message_text = ""
            for part in msg['message']:
                if part['type'] == 'text':
                    message_text += part['data']['text'].strip() + " "
                elif part['type'] == 'json':  # 处理JSON格式的分享卡片等特殊消息
                    try:
                        json_content = json.loads(part['data']['data'])
                        if 'desc' in json_content.get('meta', {}).get('news', {}):
                            message_text += f"[分享内容]{json_content['meta']['news']['desc']} "
                    except:
                        pass

                # 表情消息处理
                elif part['type'] == 'face':
                    message_text += "[表情] "
                    
                #图片信息处理
                elif part['type'] == 'image':
                    pass

            # 检查message_text的第一个字符是否为"/"，如果是则跳过当前循环（用于跳过用户调用Bot的命令）
            if message_text.startswith("/"):
                continue
            # 生成标准化的消息记录格式
            if message_text:
                chat_lines.append(f"[{msg_time}]「{nickname}」: {message_text.strip()}")

            #检查是否at了自己且单独at自己
            at_all = False
            at_me = False
            # 1. 判断有没有 @所有人
            at_all   = any(seg.get('type') == 'at' and str(seg.get('data', {}).get('qq', '')) == 'all'
                   for m in messages for seg in m.get('message', []))
        
            # 2. 判断是否单独 @机器人
            at_me    = any(seg.get('type') == 'at' and str(seg.get('data', {}).get('qq', '')) == str(myid)
                   for m in messages for seg in m.get('message', []))

            # 3. 只要单独 @机器人且没 @所有人 → 直接结束
            if at_me and not at_all:
                return
        
        # 生成最终prompt
        msg = "\n".join(chat_lines)

        # LLM处理流程
        def load_prompt():
            with open(os.path.join('data','config','astrbot_plugin_chatsummary_config.json'), 'r', encoding='utf-8-sig') as a:
                config = json.load(a)
                prompt_str = config.get('prompt',{})
                return str(prompt_str.replace('\\n','\n'))

        # 调用LLM生成总结内容
        llm_response = await self.context.get_using_provider().text_chat(
            prompt=load_prompt(),
            contexts=[
                {"role": "user", "content": str(msg)}
            ],
        )
        # 判空：None / "NULL" / "" / 仅空白
        text = (llm_response.completion_text or "").strip()
        if not text or text.upper() == "NULL":
            return #输出LLM最终总结内容，发送总结消息
        #yield event.plain_result(llm_response.completion_text)

        # 读取 Bark 配置
        Bark_config = self.config
        Token = Bark_config["Token"]
        BARK_CIPHER_KEY = Bark_config["BARK_CIPHER_KEY"]
        BARK_IV_str = Bark_config["BARK_IV"]
        icon_url = Bark_config["icon_url"]

        BARK_IV = BARK_IV_str.encode("utf-8")

        def _pkcs7_pad(data: bytes, block_bits: int = 128) -> bytes:
            padder = padding.PKCS7(block_bits).padder()
            return padder.update(data) + padder.finalize()

        def _aes256_cbc_encrypt_b64(plaintext: bytes, key: bytes, iv: bytes) -> str:
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            encryptor = cipher.encryptor()
            ct = encryptor.update(_pkcs7_pad(plaintext)) + encryptor.finalize()
            return base64.b64encode(ct).decode("utf-8")

        async def push_bark_encrypted(Name: str, text: str) -> None:
            # 1) 明文载荷
            payload = {
                "body": text,
                "title": Name,
                "icon": icon_url
            }
            plaintext = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

            # 2) 加密（固定 IV + ASCII Key）
            ciphertext_b64 = _aes256_cbc_encrypt_b64(plaintext, BARK_CIPHER_KEY.encode("utf-8"), BARK_IV)
        
            # 3) POST 到 Bark
            url = f"https://api.day.app/{Token}"
            data = {
                "ciphertext": ciphertext_b64,
                "iv": BARK_IV.decode("utf-8")  # 注意：App 接收的 IV 字符串
            }

            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
                async with session.post(url, json=data) as resp:
                    print(await resp.text())  # 调试用，可删


        asyncio.create_task(push_bark_encrypted(nickname, llm_response.completion_text))
        
