<script lang="ts">
  let {
    statusText = 'Creating your account…',
  }: {
    statusText?: string;
  } = $props();
</script>

<div class="screen">
  <div class="spinner" aria-label="Loading"></div>
  <p class="status">{statusText}</p>
</div>

<style>
  .screen {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    height: 100%;
    gap: 1.5rem;
  }

  .spinner {
    width: 48px;
    height: 48px;
    border: 4px solid #e5e7eb;
    border-top-color: #007aff;
    border-radius: 50%;
    animation: spin 0.8s linear infinite;
  }

  @keyframes spin {
    to { transform: rotate(360deg); }
  }

  .status {
    font-size: 1rem;
    color: #6b7280;
    margin: 0;
    text-align: center;
  }
</style>
