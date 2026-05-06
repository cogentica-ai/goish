# Chapter 6: Channels and Communication

Goroutines do not communicate by sharing memory; they share memory by communicating. In **Goish**, this is achieved through **Channels** and **Scoped WaitGroups**.

## 6.1 The Park/Ready Protocol

A channel in Goish is more than just a queue; it is a synchronization primitive that understands the scheduler.

### Lab Exercise 6.1: Visualizing Parking
1. Write a program where a goroutine attempts to receive from an empty channel.
2. Use `GOISH_DEBUG=chan` to watch the logs.
3. Can you find the moment the goroutine is "parked"? What is its status after parking? 

---

## 6.2 Moving Ownership: The `Send` Trait

Goish uses Rust's **Move Semantics** to make channels statically safe.

### Lab Exercise 6.2: Detecting Data Races
1. Create a `chan<Vec<u8>>`.
2. Spawn a goroutine, send a `Vec` into the channel, and then try to print the `Vec` in the parent goroutine.
3. Observe the Rust compiler error. How does this guarantee that no data races occur?

---

## 6.3 Structured Concurrency: Scoped WaitGroups

Goish introduces **Scoped WaitGroups**, enabling **Structured Concurrency**. 

### Lab Exercise 6.3: Exploring Scoped Safety
1.  Try to spawn a goroutine using `go!` that borrows a local variable. Observe the compiler error.
2.  Now use `WaitGroup.Go()` to perform the same borrow.
3.  Add a `fmt::Println` after the `WaitGroup` scope. Observe that it only prints *after* the goroutine has finished. 
4.  What happens if you use `core::mem::forget(wg)`? Does the program still wait?

---

## 6.4 The `select!` Macro: Multi-way Dispatch

The `select!` macro performs a logical port of the official Go `select` implementation.

### Lab Exercise 6.4: Select Fairness
1. Create two channels and fill them with data.
2. Run a `select!` in a loop 10 times. 
3. Does the macro always pick the first channel, or is the order randomized? 
4. Check the source code in `src/gochan.rs` to find the `cheaprand` call that ensures fairness.

---
