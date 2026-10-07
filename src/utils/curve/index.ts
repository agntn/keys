/** Curve math lives in @agntn/curves now. This subpath keeps the old import path alive. */
export {
  addPoints,
  countPoints,
  defineCurve,
  discreteLog,
  doublePoint,
  isOnCurve,
  listPoints,
  multiplyPoint,
  negatePoint,
  pointOrder,
  MAX_COUNTED_PRIME,
  MAX_FILTERED_PRIME,
  MAX_LOG_ORDER,
  MAX_ORDER_PRIME,
} from "@agntn/curves";
export type { AffinePoint, CurvePoint, ListPointsOptions, WeierstrassCurve } from "@agntn/curves";
