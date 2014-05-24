## Fibonacii的O(logN)算法

```erlang
val(N) ->
        val_iter(N, 1, 0, 0, 1).
 
val_iter(0,_,B,_,_) ->
        B;
 
val_iter(N,A,B,P,Q) ->
        R = N rem 2,
        if R =:= 1 ->
                val_iter(N - 1, B*Q+A*Q+A*P, B*P+A*Q, P, Q);
           true ->
                val_iter(N div 2,  A, B, Q*Q+P*P, Q*(2*P+Q))
        end.
```
