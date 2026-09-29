"""
自适应检索调度器 (Adaptive Retrieval Planner)。

支持两种模式：
  1. JSON Action 模式（推荐）：LLM 输出 JSON 格式的动作和理由
  2. 关键词匹配模式（向后兼容）：通过关键词匹配决定动作

JSON 格式：
{
  "action": "ExpandDFG",
  "reason": "Pointer origin is still unknown."
}

固定动作集合：
  - ExpandDFG: 扩展数据流边
  - ExpandCFG: 扩展控制流边
  - ExpandCALL: 扩展函数调用边
  - RetrieveAlias: 检索别名关系
  - CheckReachability: 检查节点间可达性
  - Stop: 停止检索
"""

import json
import re
from planning.actions import ACTIONS, ACTION_KEYWORDS


class RetrievalPlanner:

    VALID_ACTIONS = {"ExpandDFG", "ExpandCFG", "ExpandCALL",
                    "RetrieveAlias", "CheckReachability", "SummarizeEvidence", "Stop"}

    def __init__(self, use_json_mode: bool = True, agent_mode: bool = True):
        """
        初始化规划器。

        Args:
            use_json_mode: 是否使用 JSON Action 模式（推荐）
            agent_mode: 是否启用 Agent 自主决策模式（移除硬覆盖规则）
        """
        self.step = 0
        self.action_history = []
        self.use_json_mode = use_json_mode
        self.agent_mode = agent_mode

        self.dfg_expanded = False
        self.cfg_expanded = False
        self.call_expanded = False
        self.alias_retrieved = False
        self.reachability_checked = False

        self.dfg_expand_count = 0
        self.cfg_expand_count = 0
        self.call_expand_count = 0
        self.alias_retrieve_count = 0

    def parse_json_action(self, llm_output: str) -> tuple:
        """
        从 LLM 输出中解析 JSON 动作。

        Returns:
            (action, reason) 或 (None, None)
        """
        try:
            json_match = re.search(r'\{[^}]+\}', llm_output, re.DOTALL)
            if json_match:
                json_str = json_match.group()
                data = json.loads(json_str)
                action = data.get('action', '')
                reason = data.get('reason', '')

                if action in self.VALID_ACTIONS:
                    return action, reason
        except (json.JSONDecodeError, KeyError):
            pass

        return None, None

    def decide_action(self, llm_output: str) -> str:
        """
        基于 LLM 输出和当前探索状态，决定下一步动作。

        Agent 模式决策逻辑：
          1. 尝试解析 LLM 输出的 JSON 动作
          2. 如果解析成功，信任 LLM 决策（不强制覆盖）
          3. 仅做安全性检查：重复扩展计数 <= 3，最大步数保护
          4. JSON 解析失败时回退到关键词匹配
        """
        self.step += 1

        if self.use_json_mode:
            action, reason = self.parse_json_action(llm_output)

            if action:
                best_action = action
                print(f"[Planner] Agent Decision: {best_action}, Reason: {reason}")
            else:
                best_action = self._keyword_based_decision(llm_output)
                print(f"[Planner] Fallback (keyword): {best_action}")
        else:
            best_action = self._keyword_based_decision(llm_output)

        if self.agent_mode:
            best_action = self._agent_guard(best_action)
        else:
            best_action = self._apply_heuristics(best_action)

        self.action_history.append(best_action)
        self._update_expansion_state(best_action)

        if self.step >= 10:
            print("[Planner] 达到最大步数限制，强制汇总证据")
            return "SummarizeEvidence"

        return best_action

    def _agent_guard(self, action: str) -> str:
        """
        Agent 模式下的安全守卫。

        仅做最小限度的安全检查，不强制覆盖 LLM 决策：
          - 同一动作连续执行超过 3 次时建议切换
          - 动作无效时回退到 Stop
        """
        if action not in self.VALID_ACTIONS:
            return "Stop"

        repeat_limit = 6
        if action == "ExpandDFG" and self.dfg_expand_count >= repeat_limit:
            print(f"[Planner] Agent 已重复 ExpandDFG {self.dfg_expand_count} 次，建议切换但尊重决策")
        if action == "ExpandCFG" and self.cfg_expand_count >= repeat_limit:
            print(f"[Planner] Agent 已重复 ExpandCFG {self.cfg_expand_count} 次，建议切换但尊重决策")
        if action == "ExpandCALL" and self.call_expand_count >= repeat_limit:
            print(f"[Planner] Agent 已重复 ExpandCALL {self.call_expand_count} 次，建议切换但尊重决策")
        if action == "RetrieveAlias" and self.alias_retrieve_count >= repeat_limit:
            print(f"[Planner] Agent 已重复 RetrieveAlias {self.alias_retrieve_count} 次，建议切换但尊重决策")

        return action

    def get_exploration_state(self) -> str:
        """
        导出当前探索状态，供 LLM Agent 参考。
        """
        lines = [
            f"  Step: {self.step}",
            f"  Data Flow (DFG) expanded: {self.dfg_expanded} (count: {self.dfg_expand_count})",
            f"  Control Flow (CFG) expanded: {self.cfg_expanded} (count: {self.cfg_expand_count})",
            f"  Call Graph (CALL) expanded: {self.call_expanded} (count: {self.call_expand_count})",
            f"  Alias retrieved: {self.alias_retrieved} (count: {self.alias_retrieve_count})",
            f"  Reachability checked: {self.reachability_checked}",
        ]
        if self.action_history:
            lines.append(f"  Action history: {' -> '.join(self.action_history)}")
        return "\n".join(lines)

    def _keyword_based_decision(self, llm_output: str) -> str:
        """
        基于关键词的动作决策（向后兼容模式）。
        """
        llm_lower = llm_output.lower()

        action_scores = {}
        for action, keywords in ACTION_KEYWORDS.items():
            score = sum(1 for kw in keywords if kw.lower() in llm_lower)
            if score > 0:
                action_scores[action] = score

        if not action_scores:
            return "Stop"

        return max(action_scores, key=action_scores.get)

    def _apply_heuristics(self, action: str) -> str:
        """
        应用启发式规则避免重复扩展。
        """
        if action == "ExpandDFG" and self.dfg_expanded:
            if not self.cfg_expanded:
                return "ExpandCFG"
            elif not self.alias_retrieved:
                return "RetrieveAlias"
            elif not self.call_expanded:
                return "ExpandCALL"
            else:
                return "SummarizeEvidence"

        elif action == "ExpandCFG" and self.cfg_expanded:
            if not self.dfg_expanded:
                return "ExpandDFG"
            elif not self.call_expanded:
                return "ExpandCALL"
            else:
                return "SummarizeEvidence"

        elif action == "ExpandCALL" and self.call_expanded:
            if not self.alias_retrieved:
                return "RetrieveAlias"
            else:
                return "SummarizeEvidence"

        elif action == "RetrieveAlias" and self.alias_retrieved:
            return "SummarizeEvidence"

        elif action == "CheckReachability" and self.reachability_checked:
            if not self.dfg_expanded:
                return "ExpandDFG"
            elif not self.cfg_expanded:
                return "ExpandCFG"
            else:
                return "SummarizeEvidence"

        return action

    def _update_expansion_state(self, action: str):
        """
        更新探索状态（含计数）。
        """
        if action == "ExpandDFG":
            self.dfg_expanded = True
            self.dfg_expand_count += 1
        elif action == "ExpandCFG":
            self.cfg_expanded = True
            self.cfg_expand_count += 1
        elif action == "ExpandCALL":
            self.call_expanded = True
            self.call_expand_count += 1
        elif action == "RetrieveAlias":
            self.alias_retrieved = True
            self.alias_retrieve_count += 1
        elif action == "CheckReachability":
            self.reachability_checked = True

    def reset(self):
        """
        重置规划器状态。
        """
        self.step = 0
        self.action_history = []
        self.dfg_expanded = False
        self.cfg_expanded = False
        self.call_expanded = False
        self.alias_retrieved = False
        self.reachability_checked = False
        self.dfg_expand_count = 0
        self.cfg_expand_count = 0
        self.call_expand_count = 0
        self.alias_retrieve_count = 0