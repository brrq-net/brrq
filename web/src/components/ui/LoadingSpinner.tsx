'use client';

interface LoadingSpinnerProps {
  size?: 'sm' | 'md' | 'lg';
  className?: string;
}

const sizeClasses = {
  sm: 'h-4 w-4 border-2',
  md: 'h-8 w-8 border-2',
  lg: 'h-12 w-12 border-3',
};

export function LoadingSpinner({ size = 'md', className = '' }: LoadingSpinnerProps) {
  return (
    <div className={`flex items-center justify-center ${className}`}>
      <div
        className={`${sizeClasses[size]} animate-spin rounded-full border-[var(--gunmetal)] border-t-[var(--brrq-gold)]`}
      />
    </div>
  );
}

export function PageLoading() {
  return (
    <div className="flex items-center justify-center py-20">
      <div className="text-center">
        <LoadingSpinner size="lg" />
        <p className="mt-4 text-[var(--text-secondary)]">Loading...</p>
      </div>
    </div>
  );
}
