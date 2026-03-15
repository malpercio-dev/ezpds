<script lang="ts">
  let { onstart }: { onstart: () => void } = $props();
</script>

<div class="screen">
  <div class="brand">
    <h1>Identity Wallet</h1>
    <p class="tagline">Your self-sovereign identity, in your pocket.</p>
  </div>
  <button class="cta" onclick={onstart}>Get Started</button>
</div>

<style>
  .screen {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    height: 100%;
    padding: 2rem;
    gap: 3rem;
  }

  .brand {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 0.75rem;
    text-align: center;
  }

  h1 {
    font-size: 2rem;
    font-weight: 700;
    margin: 0;
  }

  .tagline {
    font-size: 1rem;
    color: #6b7280;
    margin: 0;
  }

  .cta {
    width: 100%;
    max-width: 320px;
    padding: 1rem;
    background: #007aff;
    color: #fff;
    border: none;
    border-radius: 12px;
    font-size: 1.1rem;
    font-weight: 600;
    cursor: pointer;
  }
</style>
