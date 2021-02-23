use std::cmp::max;
use std::sync::Arc;

use vec_map::VecMap;

/// Node of a binary tree.
///
/// This binary tree implementation has limited functionaly and is tailored
/// specifically for the PathORAM use case.
pub struct TreeNode {
    /// Value of the node
    value: i64,

    /// Left child of this node
    left: Option<Box<TreeNode>>,

    /// Right child of this node
    right: Option<Box<TreeNode>>,

    // caching
    pub height: usize,
    pub leaves_count: i64,
    cached: bool,
    leaves: Option<Vec<i64>>,
    path: VecMap<Arc<Vec<i64>>>,
}

impl TreeNode {
    pub fn new(value: i64) -> Self {
        Self {
            value,
            left: None,
            right: None,
            // caching
            cached: false,
            leaves: None,
            path: VecMap::new(),
            height: 0,
            leaves_count: 0,
        }
    }

    /// Create and return a binary tree of the given size
    ///
    /// # Invariants
    /// `n` must be equal to (2^k)-1 for any k >= 0
    /// In other words, `n` must be a power of two, minus one.
    pub fn create_tree(n: i64) -> TreeNode {
        let exponent = ((n + 1) as f64).log2();
        if (exponent - (exponent.round() as f64)).abs() > f64::EPSILON {
            panic!("n must be a power of 2 minus 1, e.g. n=2^3-1=7 or n=2^4-1=15")
        }

        let mut tree = TreeNode::create_tree0(n, 0).unwrap();
        tree.cached = true;
        tree.height = tree.height();
        tree.leaves_count = tree.count_leaves();
        tree
    }

    fn create_tree0(n: i64, start: i64) -> Option<TreeNode> {
        match n {
            1 => Some(TreeNode::new(start)),
            x if x < 1 => None,
            _ => {
                let max_node = start + n - 1;
                let midpoint = (max_node + start) / 2;

                let left_length = midpoint - start;
                let right_length = max_node - midpoint;

                let left = TreeNode::create_tree0(left_length, start).unwrap();
                let right = TreeNode::create_tree0(right_length, midpoint + 1).unwrap();

                let mut root = TreeNode::new(midpoint);
                root.left = Some(Box::new(left));
                root.right = Some(Box::new(right));

                Some(root)
            }
        }
    }
}

impl TreeNode {
    /// Return true if this node is a leaf
    pub fn is_leaf(&self) -> bool {
        self.left.is_none() && self.right.is_none()
    }

    #[cfg(test)]
    /// Return the number of nodes in the tree
    pub fn size(&self) -> i64 {
        if self.is_leaf() {
            1
        } else if self.left.is_none() {
            1 + self.right.as_ref().unwrap().size()
        } else if self.right.is_none() {
            1 + self.left.as_ref().unwrap().size()
        } else {
            1 + self.left.as_ref().unwrap().size() + self.right.as_ref().unwrap().size()
        }
    }

    /// Return the height of the tree
    fn height(&self) -> usize {
        if self.is_leaf() {
            0
        } else {
            let mut lh = 0;
            if self.left.is_some() {
                lh = self.left.as_ref().unwrap().height();
            }
            let mut rh = 0;
            if self.right.is_some() {
                rh = self.right.as_ref().unwrap().height();
            }
            1 + max(lh, rh)
        }
    }

    /// Return the number of leaves in the tree
    fn count_leaves(&self) -> i64 {
        if self.is_leaf() {
            1
        } else {
            let mut left_leaves = 0;
            let mut right_leaves = 0;
            if self.left.is_some() {
                left_leaves = self.left.as_ref().unwrap().count_leaves();
            }
            if self.right.is_some() {
                right_leaves = self.right.as_ref().unwrap().count_leaves();
            }
            left_leaves + right_leaves
        }
    }

    /// Return the values of the leaves in the tree
    pub fn leaves(&mut self) -> Vec<i64> {
        // caching
        if self.leaves.is_some() {
            return self.leaves.clone().unwrap();
        }

        let response = match self.is_leaf() {
            true => vec![self.value],
            false => {
                let mut left_leaves = Vec::new();
                let mut right_leaves = Vec::new();

                if self.left.is_some() {
                    left_leaves = self.left.as_mut().unwrap().leaves();
                }
                if self.right.is_some() {
                    right_leaves = self.right.as_mut().unwrap().leaves();
                }

                left_leaves.extend(right_leaves);
                left_leaves
            }
        };

        // cache
        self.leaves = Some(response.clone());
        response
    }

    /// Return the nodes on the path from the root to the node with value x
    pub fn path_to_node(&self, x: i64) -> Vec<i64> {
        if self.value == x {
            return vec![x];
        }

        let mut p = vec![self.value];
        if self.left.is_some() {
            let left_path = self.left.as_ref().unwrap().path_to_node(x);
            if left_path.contains(&x) {
                p.extend(left_path);
                return p;
            }
        }

        if self.right.is_some() {
            let right_path = self.right.as_ref().unwrap().path_to_node(x);
            if right_path.contains(&x) {
                p.extend(right_path);
                return p;
            }
        }
        return vec![];
    }

    /// Return the path from the root to the `x`th leaf (0-based).
    /// Path from leaf to root is called P(x) in Path ORAM
    pub fn path(&mut self, x: i64) -> Arc<Vec<i64>> {
        if let Some(val) = self.path.get(x as usize) {
            return val.clone();
        }

        let leaves = self.leaves();
        let x_value = leaves.get(x as usize).unwrap_or_else(|| {
            panic!(
                "Cannot obtain {}th leaf because there are not that many leaves",
                x
            )
        });

        // cache
        let response = Arc::new(self.path_to_node(*x_value));
        self.path.insert(x as usize, response.clone());
        response
    }

    /// Get the node at level l from the path from root to xth leaf (0-based)
    /// Also called P(x, l) in Path ORAM
    /// level=0 => root
    /// level=L => leaves
    pub fn pathl(&mut self, x: i64, level: usize) -> i64 {
        let p = self.path(x);
        *p.get(level).unwrap()
    }
}

#[cfg(test)]
mod test {
    use crate::oram::pathoram::tree::TreeNode;

    #[test]
    fn test_create_tree() {
        let t = TreeNode::create_tree(15);
        assert_eq!(t.size(), 15);
        assert_eq!(t.count_leaves(), 8);
    }

    #[test]
    fn test_path() {
        let mut t = TreeNode::create_tree(7);
        let p = t.path(3).to_vec();
        assert_eq!(p, vec![3, 5, 6]);
    }

    #[test]
    fn test_pathl() {
        let mut t = TreeNode::create_tree(7);
        let x = t.pathl(3, 1);
        assert_eq!(x, 5);
    }

    #[test]
    fn test_height() {
        let t = TreeNode::create_tree(7);
        let l = t.height();
        assert_eq!(l, 2);

        let t2 = TreeNode::create_tree(15);
        let l2 = t2.height();
        assert_eq!(l2, 3);
    }

    #[test]
    fn test_leaves() {
        let mut t = TreeNode::create_tree(7);
        let leaves = t.leaves();
        assert_eq!(leaves, vec![0, 2, 4, 6]);
    }

    #[test]
    fn test_leaves_count() {
        let t = TreeNode::create_tree(7);
        let count = t.count_leaves();
        assert_eq!(count, 4);
    }
}
