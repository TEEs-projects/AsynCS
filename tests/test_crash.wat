(module
  (memory (export "memory") 1)
  (func (export "_start")
    i32.const 1
    i32.const 0
    i32.div_s
    drop
  )
  (func (export "main") (param i32 i32) (result i32)
    i32.const 1
    i32.const 0
    i32.div_s
  )
)
