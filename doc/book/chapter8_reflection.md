# Chapter 8: Reflection and Introspection

In **Goish**, we achieve Go-style runtime type inspection through a combination of procedural macros and a sophisticated `reflect` package.

## 8.1 Compile-time Reflection via Proc-Macros

Goish uses the `#[goish::reflect]` macro to generate static type descriptors.

### Lab Exercise 8.1: Macro Introspection
1. Use `cargo expand` on a struct decorated with `#[goish::reflect]`.
2. Can you find the generated `Reflect` trait implementation? 
3. Look at the `__reflect_type` function. How is the field information stored?

---

## 8.2 The `reflect` Package

The `reflect` package provides the user-facing API for introspection.

### Lab Exercise 8.2: Dynamic Inspection
1. Create a struct with several fields.
2. Use the `reflect` package to iterate over all fields and print their names and types.
3. Use `reflect::ValueOf(&obj)` to get a mirror of the data. Can you print the values of the fields dynamically?

---

## 8.3 Struct Tags

Goish supports Go-style struct tags.

### Lab Exercise 8.3: Custom Tag Logic
1. Define a struct `User` with a field `ID` and a tag `#[tag(my_custom_tag="secret_key")]`.
2. Use the `reflect` package to retrieve the value of `my_custom_tag`.
3. Write a small helper function that takes any struct and prints only the fields that have a specific tag.

---
