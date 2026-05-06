# Chapter 4: Error Handling

In Goish, error handling follows the classic Go idiom: "Errors are values." However, these values are implemented using Rust's sophisticated type system to ensure they are both efficient and thread-safe.

## 4.1 The `error` Interface and `nil` checks

In Goish, an `error` is a newtype around `Option<Arc<dyn ErrorTrait>>`. 

```rust
pub trait ErrorTrait: Any + Send + Sync + 'static {
    fn Error(&self) -> string;
    fn Unwrap(&self) -> error { nil }
}
```

This definition ensures that:
-   Any type that implements `Error()` can be an error.
-   Errors can be safely sent between goroutines (`Send + Sync`).
-   Errors can be compared against `nil`.

### Lab Exercise 4.1: The Nil Error
1. Create a function that returns an `error`. 
2. Inside the function, `return nil.into();`. 
3. In `main`, call the function and check `if err == nil`. 
4. Try to call `err.Error()` when `err` is `nil`. What happens? (Check the `panic` message in `src/errors/mod.rs`).

---

## 4.2 Creating and Wrapping Errors

Goish provides `errors::New` for simple messages and `errors::Wrap` for custom types.

```rust
let err = errors::New("something went wrong");

struct MyError { code: int }
impl ErrorTrait for MyError {
    fn Error(&self) -> string { string("error code X") }
}
return errors::Wrap(MyError { code: 500 });
```

### Lab Exercise 4.2: Distinct Identities
1. Create two errors with the exact same message: `let e1 = errors::New("fail"); let e2 = errors::New("fail");`.
2. Compare them: `if e1 == e2`. 
3. Does the comparison return true or false? Why? (Hint: Check the "Pointer Identity" section in `src/errors/mod.rs`).

---

## 4.3 Error Chaining: `Is` and `As`

Goish supports Go-style error wrapping and inspection using `errors::Is` and `errors::As`.

-   **`errors::Is(err, target)`**: Checks if any error in the chain matches a specific sentinel or instance.
-   **`errors::As::<T>(err)`**: Finds the first error of type `T` and returns a reference to it.

```rust
if let Some(my_err) = errors::As::<MyError>(err) {
    fmt::Println("Found code: ", my_err.code);
}
```

### Lab Exercise 4.3: Walking the Chain
1. Define a custom error type that wraps another error by overriding the `Unwrap()` method.
2. Create a chain of three errors.
3. Use `errors::Is` to find the middle error in the chain.
4. Use `errors::As` to extract the data from the custom error type at the bottom of the chain.

---

## 4.4 Combining Errors with `Join`

Goish 1.25 includes `errors::Join`, which allows you to aggregate multiple errors into a single value.

```rust
let errs = slice!([e1, e2, e3]);
let combined = errors::Join(errs);
fmt::Println(combined); // Prints each error separated by newlines
```

### Lab Exercise 4.4: Multi-Error Inspection
1. Create a slice of four errors, where two are `nil`.
2. Call `errors::Join(errs)`. 
3. Print the result. Are the `nil` errors included in the output? 
4. Call `Unwrap()` on the joined error. Which of the original errors do you get back?

---

## 4.5 Panic and Recovery

While Goish encourages the "check errors early" pattern, some situations are unrecoverable bugs (like a nil pointer dereference or a failed assertion). These trigger a **Panic**.

Goish's `panic!` and `recover!` mechanisms mirror Go's behavior but are built on Rust's low-level runtime hooks.

### 4.5.1 Panic-Safe `defer!`
In standard Go, `defer` statements run even when a function panics. Goish achieves this by registering every `defer!` block with a per-goroutine **Cleanup List**. 

When a panic occurs:
1.  The runtime intercepts the panic via the `#[panic_handler]`.
2.  It walks the cleanup list and executes every `defer!` block in LIFO order.
3.  Only after all defers have run does the goroutine terminate.

### 4.5.2 Observing Panics with `recover!`
Inside a `defer!` block, you can use `recover!()` to observe if a panic is in progress and retrieve its message as a Goish `error`.

```rust
defer!{
    let e = recover!();
    if e != nil {
        log::Printf("Caught panic: %v", e);
    }
}
```

*   **Difference from Go**: In standard Go, `recover()` stops the panic and allows the function to resume. In Goish v1, **`recover!()` is for observation only**. The goroutine will still terminate after the defers finish. This is a deliberate design choice to maintain predictability in a `no_std` environment.

### 4.5.3 Panic Diagnostics
When a process panics and aborts, Goish provides enhanced panic diagnostics. The `#[panic_handler]` (in `src/runtime/mod.rs`) prints not only the panic message and file/line location, but also critical preemption statistics (invocations, injections, and skip breakdowns) and the most recent injection PCs. This helps developers correlate a panic with asynchronous events (like `SIGURG` preemption), which is crucial for debugging race conditions in a stackful runtime.

### Lab Exercise 4.5: Panic Observation
1. Write a function that calls `panic!("boom")`. 
2. Add a `defer!` block before the panic that calls `recover!()`. 
3. Print the value returned by `recover!()`. 
4. Verify that the panic message "boom" is captured correctly. 
5. Does the code after the `panic!` call ever execute?

---
