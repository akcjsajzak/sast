"""Per-language node-type profiles for the generic taint engine.

PHP, Java and JavaScript each have a hand-tuned engine because each has
framework quirks worth special-casing. The remaining languages differ from
each other mostly in what tree-sitter *calls* things — a call is a call, an
assignment is an assignment — so they share one engine, configured here.

Adding a language is then a profile plus a rule set, not another engine.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class LangProfile:
    """Node type names and conventions for one language."""
    name: str

    # Expressions
    call: tuple = ()             # call expression node types
    member: tuple = ()           # attribute/field access node types
    index: tuple = ()            # subscript node types
    identifier: tuple = ("identifier",)
    literal: tuple = ()          # nodes that are never tainted
    binary: tuple = ()           # concatenation-capable binary expressions
    concat_ops: tuple = ("+",)   # operators that join strings
    # Tags that survive arithmetic. `a / b` is not a string an attacker
    # controls, so sql/cmd/xss must not pass through it — but it *is* a number
    # an attacker influences, which is the whole of CWE-190 and CWE-129.
    # Dropping everything meant `malloc(w * h)` and `buf[w / h]` were
    # invisible while `malloc(w + h)` was found, purely because `+` happens to
    # double as string concatenation.
    numeric_tags: tuple = ()
    transparent: tuple = ()      # wrappers that pass taint straight through
    ternary: tuple = ()
    interpolation: tuple = ()    # f-strings / template literals
    interpolation_hole: tuple = ()  # the expression slot inside one

    # Statements
    assignment: tuple = ()
    aug_assignment: tuple = ()
    declaration: tuple = ()      # variable declaration statements
    declarator: tuple = ()       # a single name=value inside a declaration
    return_stmt: tuple = ()
    block: tuple = ()            # statement block / body
    branch: tuple = ()           # if / switch / match
    loop: tuple = ()
    try_stmt: tuple = ()
    expression_stmt: tuple = ()

    # Functions and classes
    function: tuple = ()
    method: tuple = ()
    class_def: tuple = ()
    params: tuple = ()           # formal parameter list nodes
    param: tuple = ()            # a single parameter node

    # Field names used by this grammar (tree-sitter field accessors)
    f_function: str = "function"
    f_arguments: str = "arguments"
    f_object: str = "object"
    f_property: str = "field"
    f_left: str = "left"
    f_right: str = "right"
    f_name: str = "name"
    f_value: str = "value"
    f_body: str = "body"
    f_operator: str = "operator"
    f_condition: str = "condition"
    f_parameters: str = "parameters"

    # Conventions
    self_names: tuple = ("self", "this")
    # True when a bare call's callee is written `pkg.func(...)`, so the engine
    # should treat the member root as the receiver hint.
    dotted_calls: bool = True
    # True when a method declares the object it is called on as its first
    # parameter (Python's `self`, or `cls` for a classmethod). A call written
    # `obj.m(a)` then binds `a` to the *second* declared parameter.
    implicit_receiver: bool = False
    # True when import statements and definitions bind module-level names
    # (Python). A call to a name the file defines, or imports from first-party
    # code, is to project code and never matches a library sink of that name.
    module_bindings: bool = False
    # Comment node types to skip.
    comment: tuple = ("comment", "line_comment", "block_comment")
    # Extra node types that introduce a new name binding (for-loop variables).
    loop_binding: tuple = ()
    f_loop_left: str = "left"
    f_loop_right: str = "right"
    extra: dict = field(default_factory=dict)


PYTHON = LangProfile(
    name="python",
    call=("call",),
    member=("attribute",),
    index=("subscript",),
    literal=("string", "integer", "float", "true", "false", "none",
             "concatenated_string"),
    binary=("binary_operator",),
    concat_ops=("+", "%"),
    transparent=("parenthesized_expression", "await", "expression_statement",
                 "not_operator", "as_pattern"),
    ternary=("conditional_expression",),
    interpolation=("string",),
    interpolation_hole=("interpolation",),
    assignment=("assignment",),
    aug_assignment=("augmented_assignment",),
    return_stmt=("return_statement",),
    block=("block", "module"),
    branch=("if_statement", "match_statement", "case_clause", "elif_clause",
            "else_clause"),
    loop=("for_statement", "while_statement"),
    try_stmt=("try_statement", "except_clause", "finally_clause", "with_statement"),
    expression_stmt=("expression_statement",),
    function=("function_definition",),
    method=("function_definition",),
    class_def=("class_definition",),
    params=("parameters", "lambda_parameters"),
    param=("identifier", "typed_parameter", "default_parameter",
           "typed_default_parameter", "list_splat_pattern",
           "dictionary_splat_pattern"),
    f_property="attribute",
    f_arguments="arguments",
    self_names=("self", "cls"),
    implicit_receiver=True,
    module_bindings=True,
    loop_binding=("for_statement",),
    f_loop_left="left",
    f_loop_right="right",
)

GO = LangProfile(
    name="go",
    call=("call_expression",),
    member=("selector_expression",),
    index=("index_expression",),
    literal=("interpreted_string_literal", "raw_string_literal", "int_literal",
             "float_literal", "true", "false", "nil", "rune_literal"),
    binary=("binary_expression",),
    concat_ops=("+",),
    transparent=("parenthesized_expression", "type_conversion_expression",
                 "unary_expression"),
    assignment=("assignment_statement",),
    aug_assignment=("assignment_statement",),
    declaration=("var_declaration", "short_var_declaration", "const_declaration"),
    declarator=("var_spec", "const_spec"),
    return_stmt=("return_statement",),
    # Go nests a function body's statements one level deeper, inside a
    # statement_list; without it every statement would be read as a bare
    # expression and assignments would never bind.
    block=("block", "source_file", "statement_list"),
    branch=("if_statement", "expression_switch_statement", "type_switch_statement",
            "expression_case", "default_case", "communication_case"),
    loop=("for_statement", "range_clause"),
    try_stmt=("defer_statement", "go_statement"),
    expression_stmt=("expression_statement",),
    function=("function_declaration",),
    method=("method_declaration",),
    class_def=("type_declaration",),
    params=("parameter_list",),
    param=("parameter_declaration", "variadic_parameter_declaration"),
    f_property="field",
    f_object="operand",
    f_function="function",
    f_arguments="arguments",
    self_names=(),
    comment=("comment",),
    loop_binding=("range_clause",),
)

CSHARP = LangProfile(
    name="csharp",
    call=("invocation_expression", "object_creation_expression"),
    member=("member_access_expression",),
    index=("element_access_expression",),
    literal=("string_literal", "verbatim_string_literal", "integer_literal",
             "real_literal", "boolean_literal", "null_literal",
             "character_literal"),
    binary=("binary_expression",),
    concat_ops=("+",),
    transparent=("parenthesized_expression", "await_expression", "cast_expression",
                 "postfix_unary_expression", "prefix_unary_expression"),
    ternary=("conditional_expression",),
    interpolation=("interpolated_string_expression",),
    interpolation_hole=("interpolation",),
    assignment=("assignment_expression",),
    declaration=("local_declaration_statement", "field_declaration",
                 "variable_declaration"),
    declarator=("variable_declarator",),
    return_stmt=("return_statement",),
    block=("block", "compilation_unit"),
    branch=("if_statement", "switch_statement", "switch_section", "else_clause"),
    loop=("for_statement", "foreach_statement", "while_statement", "do_statement"),
    try_stmt=("try_statement", "catch_clause", "finally_clause", "using_statement"),
    expression_stmt=("expression_statement",),
    function=("method_declaration", "local_function_statement"),
    method=("method_declaration",),
    class_def=("class_declaration", "record_declaration", "struct_declaration"),
    params=("parameter_list",),
    param=("parameter",),
    f_property="name",
    f_object="expression",
    f_function="function",
    f_arguments="arguments",
    self_names=("this",),
    loop_binding=("foreach_statement",),
    f_loop_left="left",
    f_loop_right="right",
)

C = LangProfile(
    name="c",
    call=("call_expression",),
    member=("field_expression",),
    index=("subscript_expression",),
    literal=("string_literal", "number_literal", "char_literal", "null",
             "true", "false"),
    binary=("binary_expression",),
    concat_ops=("+",),
    numeric_tags=("int", "buffer"),
    transparent=("parenthesized_expression", "cast_expression",
                 "pointer_expression", "unary_expression"),
    ternary=("conditional_expression",),
    assignment=("assignment_expression",),
    declaration=("declaration",),
    declarator=("init_declarator",),
    return_stmt=("return_statement",),
    block=("compound_statement", "translation_unit"),
    branch=("if_statement", "switch_statement", "case_statement", "else_clause"),
    loop=("for_statement", "while_statement", "do_statement"),
    expression_stmt=("expression_statement",),
    function=("function_definition",),
    class_def=("struct_specifier",),
    params=("parameter_list",),
    param=("parameter_declaration",),
    f_property="field",
    f_object="argument",
    f_function="function",
    f_arguments="arguments",
    f_name="declarator",
    self_names=(),
    dotted_calls=False,
)

CPP = LangProfile(
    name="cpp",
    call=("call_expression", "new_expression"),
    member=("field_expression",),
    index=("subscript_expression",),
    literal=("string_literal", "number_literal", "char_literal", "nullptr",
             "true", "false", "raw_string_literal"),
    binary=("binary_expression",),
    concat_ops=("+", "<<"),
    numeric_tags=("int", "buffer"),
    transparent=("parenthesized_expression", "cast_expression",
                 "pointer_expression", "unary_expression",
                 "static_cast_expression", "reinterpret_cast_expression"),
    ternary=("conditional_expression",),
    assignment=("assignment_expression",),
    declaration=("declaration",),
    declarator=("init_declarator",),
    return_stmt=("return_statement",),
    block=("compound_statement", "translation_unit"),
    branch=("if_statement", "switch_statement", "case_statement", "else_clause"),
    loop=("for_statement", "while_statement", "do_statement",
          "for_range_loop"),
    try_stmt=("try_statement", "catch_clause"),
    expression_stmt=("expression_statement",),
    function=("function_definition",),
    class_def=("class_specifier", "struct_specifier"),
    params=("parameter_list",),
    param=("parameter_declaration",),
    f_property="field",
    f_object="argument",
    f_function="function",
    f_arguments="arguments",
    f_name="declarator",
    self_names=("this",),
    dotted_calls=True,
)

PROFILES = {
    "python": PYTHON,
    "go": GO,
    "csharp": CSHARP,
    "c": C,
    "cpp": CPP,
}
