import os
from datetime import datetime
import json
from astrbot.api.event import filter, AstrMessageEvent
from astrbot.api.star import Context, Star, register

@register("astrbot_plugin_chatsummary", "laopanmemz", "一个基于LLM的历史聊天记录总结插件", "1.0.4")
# 聊天记录总结插件主类，继承自Star基类
class ChatSummary(Star):
    # 初始化插件实例
    def __init__(self, context: Context):
        super().__init__(context)

    # 注册指令的装饰器。指令名为 消息总结 。注册成功后，发送 `/消息总结` 就会触发这个指令。
    @filter.command("消息总结")  # 消息历史获取与处理
    async def summary(self, event: AstrMessageEvent, count: int = None, seq: int = 0):
        """触发消息总结，命令加空格，后面跟获取聊天记录的数量即可（例如“ /消息总结 20 ”），可选跟序号，从新倒旧，默认从0开始计序号（例如“ /消息总结 20 500 ”）"""
        from astrbot.core.platform.sources.aiocqhttp.aiocqhttp_message_event import AiocqhttpMessageEvent
        assert isinstance(event, AiocqhttpMessageEvent)
        client = event.bot

        # 检查是否传入了要总结的聊天记录数量，未传入则返回错误，并终止事件传播
        if count is None:
            yield event.plain_result("未传入要总结的聊天记录数量\n请按照「 /消息总结 [要总结的聊天记录数量] [可选：从序号多少开始总结（默认为0，即最新记录）] 」格式发送\n例如「 /消息总结 114 500」~")
            event.stop_event()
            return

        # 构造获取群消息历史的请求参数
        payloads = {
          "group_id": event.get_group_id(),
          "message_seq": seq,
          "count": count,
          "reverseOrder": False
        }

        # 调用API获取群聊历史消息
        ret = await client.api.call_action("get_group_msg_history", **payloads)

        myid_post = await client.api.call_action("get_login_info", **payloads)
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

            # 检查message_text的第一个字符是否为"/"，如果是则跳过当前循环（用于跳过用户调用Bot的命令）
            if message_text.startswith("/"):
                continue

            # 生成标准化的消息记录格式
            if message_text:
                chat_lines.append(f"[{msg_time}]「{nickname}」: {message_text.strip()}")

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

        # 输出LLM最终总结内容，发送总结消息
        yield event.plain_result(llm_response.completion_text)
