<script lang="ts">
  import { greet } from '$lib/ipc';

  let name = $state('World');
  let greetMsg = $state('');

  async function handleGreet() {
    greetMsg = await greet(name);
  }
</script>

<main>
  <h1>Identity Wallet</h1>
  <div class="greet-form">
    <input
      type="text"
      bind:value={name}
      placeholder="Enter a name"
    />
    <button onclick={handleGreet}>Greet</button>
  </div>
  {#if greetMsg}
    <p class="greeting">{greetMsg}</p>
  {/if}
</main>

<style>
  main {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    min-height: 100vh;
    padding: 1rem;
    font-family: system-ui, sans-serif;
    box-sizing: border-box;
  }

  .greet-form {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
    width: 100%;
    max-width: 280px;
    margin-top: 1rem;
  }

  input,
  button {
    padding: 0.5rem;
    font-size: 1rem;
    border-radius: 4px;
    border: 1px solid #ccc;
    box-sizing: border-box;
    width: 100%;
  }

  button {
    cursor: pointer;
    background: #007aff;
    color: white;
    border-color: #007aff;
  }

  .greeting {
    margin-top: 1rem;
    font-size: 1.25rem;
  }
</style>
