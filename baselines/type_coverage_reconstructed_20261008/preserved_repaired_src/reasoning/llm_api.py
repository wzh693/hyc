"""
LLM API 接口封装。

支持 OpenAI 兼容 API（Qwen, Llama, DeepSeek 等）。
"""

from config import LLM_API_KEY, LLM_BASE_URL, LLM_MODEL
from reasoning.prompts import get_system_prompt
from contextvars import ContextVar

_CALL_METADATA = ContextVar('hgl_call_metadata', default=None)


def reset_call_metadata():
    _CALL_METADATA.set(None)


def get_call_metadata():
    return dict(_CALL_METADATA.get() or {})


def create_client():
    """创建 LLM 客户端。"""
    from openai import OpenAI
    return OpenAI(api_key=LLM_API_KEY, base_url=LLM_BASE_URL, max_retries=0, timeout=90)


def query_llm(prompt: str, client=None, *, bounded_output=False) -> tuple:
    """
    调用 LLM 进行推理。

    参数:
        prompt: 用户 prompt
        client: OpenAI 客户端（可选，不传则自动创建）
    返回:
        (LLM 响应文本, 总 token 数)
    """
    if client is None:
        client = create_client()

    reset_call_metadata()
    response = client.chat.completions.create(
        model=LLM_MODEL,
        messages=[
            {"role": "system", "content": get_system_prompt(prompt, bounded_output=bounded_output)},
            {"role": "user", "content": prompt},
        ],
        temperature=0.0,
        # 100 会在词中截断 HYPOTHESIS 行 → 类型提取失败（v10 三个噪声 FN 嫌疑），
        # 150 留出格式行余量，仍保持极简输出
        max_tokens=150,
    )
    usage = response.usage.total_tokens if response.usage else 0
    _CALL_METADATA.set({
        'finish_reason': response.choices[0].finish_reason,
        'prompt_tokens': getattr(response.usage, 'prompt_tokens', None),
        'completion_tokens': getattr(response.usage, 'completion_tokens', None),
        'model': response.model,
    })
    return response.choices[0].message.content, usage


def query_llm_with_retry(
    prompt: str,
    client=None,
    max_retries: int = 3,
    *, bounded_output=False,
) -> tuple:
    """
    带重试的 LLM 查询。
    返回: (LLM 响应文本, 总 token 数)
    """
    import time

    if client is None:
        client = create_client()

    for attempt in range(max_retries):
        try:
            return (query_llm(prompt, client, bounded_output=True) if bounded_output
                    else query_llm(prompt, client))
        except Exception as e:
            print(f"[LLM] 查询失败 (attempt {attempt+1}/{max_retries}): {e}")
            if attempt < max_retries - 1:
                time.sleep(2 ** attempt)
            else:
                raise
