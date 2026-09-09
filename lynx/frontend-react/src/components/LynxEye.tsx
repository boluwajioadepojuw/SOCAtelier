// Lynx mark: an amber eye in the dark. Used in the top bar and as the favicon.
export default function LynxEye({ size = 16 }: { size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      aria-label="Lynx"
    >
      <defs>
        <linearGradient id="lynx-iris" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0%" stopColor="#f2c46b" />
          <stop offset="55%" stopColor="#e0a23c" />
          <stop offset="100%" stopColor="#b97a1e" />
        </linearGradient>
      </defs>
      <path
        d="M2 12 Q 6 4.5 12 4.5 Q 18 4.5 22 12 Q 18 19.5 12 19.5 Q 6 19.5 2 12 Z"
        stroke="#e0a23c"
        strokeWidth="1.4"
        fill="rgba(224,162,60,0.07)"
      />
      <circle cx="12" cy="12" r="5.1" fill="url(#lynx-iris)" />
      <ellipse cx="12" cy="12" rx="1.55" ry="4.9" fill="#0a0908" />
      <circle cx="13.6" cy="10.2" r="1.15" fill="rgba(255,255,255,0.55)" />
    </svg>
  )
}
