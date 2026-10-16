// Skill 列表面板 — 调用后端 @ui.action 展示已加载 skill
// 说明：按 N.E.K.O 插件 UI 约定，通过 api.call 调用后端 action；
// 骨架可跑通，具体组件名以宿主 SDK 实际导出为准。
import React, { useEffect, useState } from 'react'

type SkillItem = { name: string; description: string; path: string; kind: string }

export default function SkillsPanel() {
  const [skills, setSkills] = useState<SkillItem[]>([])
  const [status, setStatus] = useState('加载中...')
  const [keyword, setKeyword] = useState('')

  const refresh = async () => {
    try {
      // 调用后端 get_skill_list（@ui.action）
      const res = await (window as any).api?.call?.('get_skill_list', {}) ?? {}
      setSkills(res?.skills ?? [])
      setStatus(`已加载 ${res?.count ?? 0} 个 skill`)
    } catch (e) {
      setStatus('加载失败：' + String(e))
    }
  }

  useEffect(() => { refresh() }, [])

  const shown = skills.filter(s =>
    !keyword || (s.name + s.description).toLowerCase().includes(keyword.toLowerCase())
  )

  return (
    <div style={{ padding: 16, fontFamily: 'system-ui' }}>
      <div style={{ display: 'flex', gap: 8, marginBottom: 12, alignItems: 'center' }}>
        <h3 style={{ margin: 0, flex: 1 }}>已加载 Skill</h3>
        <input
          value={keyword}
          onChange={e => setKeyword(e.target.value)}
          placeholder="搜索 skill"
          style={{ padding: '6px 10px', border: '1px solid #d1d5db', borderRadius: 6 }}
        />
        <button onClick={refresh} style={{ padding: '6px 12px', borderRadius: 6, cursor: 'pointer' }}>
          刷新
        </button>
      </div>
      <div style={{ color: '#6b7280', fontSize: 12, marginBottom: 12 }}>{status}</div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
        {shown.map(s => (
          <div key={s.path} style={{ border: '1px solid #e5e7eb', borderRadius: 8, padding: 12 }}>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              <strong>{s.name}</strong>
              <span style={{
                fontSize: 11, padding: '2px 6px', borderRadius: 4,
                background: s.kind === 'symlink' ? '#fef3c7' : '#e0e7ff'
              }}>{s.kind}</span>
            </div>
            <div style={{ color: '#6b7280', fontSize: 13, marginTop: 4 }}>{s.description || '（无描述）'}</div>
            <div style={{ color: '#9ca3af', fontSize: 11, marginTop: 4 }}>{s.path}</div>
          </div>
        ))}
        {shown.length === 0 && <div style={{ color: '#9ca3af' }}>无匹配 skill</div>}
      </div>
    </div>
  )
}
