/* generated by rust_qt_binding_generator */
use libc::{c_char, c_ushort, c_int};
use std::slice;
use std::char::decode_utf16;

use std::sync::Arc;
use std::sync::atomic::{AtomicPtr, Ordering};
use std::ptr::null;

use implementation::*;


#[repr(C)]
pub struct COption<T> {
    data: T,
    some: bool,
}

impl<T> COption<T> {
    #![allow(dead_code)]
    fn into(self) -> Option<T> {
        if self.some {
            Some(self.data)
        } else {
            None
        }
    }
}

impl<T> From<Option<T>> for COption<T>
where
    T: Default,
{
    fn from(t: Option<T>) -> COption<T> {
        if let Some(v) = t {
            COption {
                data: v,
                some: true,
            }
        } else {
            COption {
                data: T::default(),
                some: false,
            }
        }
    }
}


pub enum QString {}

fn set_string_from_utf16(s: &mut String, str: *const c_ushort, len: c_int) {
    let utf16 = unsafe { slice::from_raw_parts(str, to_usize(len)) };
    let characters = decode_utf16(utf16.iter().cloned())
        .map(|r| r.unwrap());
    s.clear();
    s.extend(characters);
}



#[repr(C)]
#[derive(PartialEq, Eq, Debug)]
pub enum SortOrder {
    Ascending = 0,
    Descending = 1,
}

#[repr(C)]
pub struct QModelIndex {
    row: c_int,
    internal_id: usize,
}


fn to_usize(n: c_int) -> usize {
    if n < 0 {
        panic!("Cannot cast {} to usize", n);
    }
    n as usize
}


fn to_c_int(n: usize) -> c_int {
    if n > c_int::max_value() as usize {
        panic!("Cannot cast {} to c_int", n);
    }
    n as c_int
}


pub struct TodosQObject {}

pub struct TodosEmitter {
    qobject: Arc<AtomicPtr<TodosQObject>>,
    active_count_changed: fn(*mut TodosQObject),
    count_changed: fn(*mut TodosQObject),
    new_data_ready: fn(*mut TodosQObject),
}

unsafe impl Send for TodosEmitter {}

impl TodosEmitter {
    /// Clone the emitter
    ///
    /// The emitter can only be cloned when it is mutable. The emitter calls
    /// into C++ code which may call into Rust again. If emmitting is possible
    /// from immutable structures, that might lead to access to a mutable
    /// reference. That is undefined behaviour and forbidden.
    pub fn clone(&mut self) -> TodosEmitter {
        TodosEmitter {
            qobject: self.qobject.clone(),
            active_count_changed: self.active_count_changed,
            count_changed: self.count_changed,
            new_data_ready: self.new_data_ready,
        }
    }
    fn clear(&self) {
        let n: *const TodosQObject = null();
        self.qobject.store(n as *mut TodosQObject, Ordering::SeqCst);
    }
    pub fn active_count_changed(&mut self) {
        let ptr = self.qobject.load(Ordering::SeqCst);
        if !ptr.is_null() {
            (self.active_count_changed)(ptr);
        }
    }
    pub fn count_changed(&mut self) {
        let ptr = self.qobject.load(Ordering::SeqCst);
        if !ptr.is_null() {
            (self.count_changed)(ptr);
        }
    }
    pub fn new_data_ready(&mut self) {
        let ptr = self.qobject.load(Ordering::SeqCst);
        if !ptr.is_null() {
            (self.new_data_ready)(ptr);
        }
    }
}

#[derive(Clone)]
pub struct TodosList {
    qobject: *mut TodosQObject,
    layout_about_to_be_changed: fn(*mut TodosQObject),
    layout_changed: fn(*mut TodosQObject),
    data_changed: fn(*mut TodosQObject, usize, usize),
    begin_reset_model: fn(*mut TodosQObject),
    end_reset_model: fn(*mut TodosQObject),
    begin_insert_rows: fn(*mut TodosQObject, usize, usize),
    end_insert_rows: fn(*mut TodosQObject),
    begin_move_rows: fn(*mut TodosQObject, usize, usize, usize),
    end_move_rows: fn(*mut TodosQObject),
    begin_remove_rows: fn(*mut TodosQObject, usize, usize),
    end_remove_rows: fn(*mut TodosQObject),
}

impl TodosList {
    pub fn layout_about_to_be_changed(&mut self) {
        (self.layout_about_to_be_changed)(self.qobject);
    }
    pub fn layout_changed(&mut self) {
        (self.layout_changed)(self.qobject);
    }
    pub fn data_changed(&mut self, first: usize, last: usize) {
        (self.data_changed)(self.qobject, first, last);
    }
    pub fn begin_reset_model(&mut self) {
        (self.begin_reset_model)(self.qobject);
    }
    pub fn end_reset_model(&mut self) {
        (self.end_reset_model)(self.qobject);
    }
    pub fn begin_insert_rows(&mut self, first: usize, last: usize) {
        (self.begin_insert_rows)(self.qobject, first, last);
    }
    pub fn end_insert_rows(&mut self) {
        (self.end_insert_rows)(self.qobject);
    }
    pub fn begin_move_rows(&mut self, first: usize, last: usize, destination: usize) {
        (self.begin_move_rows)(self.qobject, first, last, destination);
    }
    pub fn end_move_rows(&mut self) {
        (self.end_move_rows)(self.qobject);
    }
    pub fn begin_remove_rows(&mut self, first: usize, last: usize) {
        (self.begin_remove_rows)(self.qobject, first, last);
    }
    pub fn end_remove_rows(&mut self) {
        (self.end_remove_rows)(self.qobject);
    }
}

pub trait TodosTrait {
    fn new(emit: TodosEmitter, model: TodosList) -> Self;
    fn emit(&mut self) -> &mut TodosEmitter;
    fn active_count(&self) -> u64;
    fn count(&self) -> u64;
    fn add(&mut self, description: String) -> ();
    fn clear_completed(&mut self) -> ();
    fn remove(&mut self, index: u64) -> bool;
    fn set_all(&mut self, completed: bool) -> ();
    fn row_count(&self) -> usize;
    fn insert_rows(&mut self, _row: usize, _count: usize) -> bool { false }
    fn remove_rows(&mut self, _row: usize, _count: usize) -> bool { false }
    fn can_fetch_more(&self) -> bool {
        false
    }
    fn fetch_more(&mut self) {}
    fn sort(&mut self, u8, SortOrder) {}
    fn completed(&self, index: usize) -> bool;
    fn set_completed(&mut self, index: usize, bool) -> bool;
    fn description(&self, index: usize) -> &str;
    fn set_description(&mut self, index: usize, String) -> bool;
}

#[no_mangle]
pub extern "C" fn todos_new(
    todos: *mut TodosQObject,
    todos_active_count_changed: fn(*mut TodosQObject),
    todos_count_changed: fn(*mut TodosQObject),
    todos_new_data_ready: fn(*mut TodosQObject),
    todos_layout_about_to_be_changed: fn(*mut TodosQObject),
    todos_layout_changed: fn(*mut TodosQObject),
    todos_data_changed: fn(*mut TodosQObject, usize, usize),
    todos_begin_reset_model: fn(*mut TodosQObject),
    todos_end_reset_model: fn(*mut TodosQObject),
    todos_begin_insert_rows: fn(*mut TodosQObject, usize, usize),
    todos_end_insert_rows: fn(*mut TodosQObject),
    todos_begin_move_rows: fn(*mut TodosQObject, usize, usize, usize),
    todos_end_move_rows: fn(*mut TodosQObject),
    todos_begin_remove_rows: fn(*mut TodosQObject, usize, usize),
    todos_end_remove_rows: fn(*mut TodosQObject),
) -> *mut Todos {
    let todos_emit = TodosEmitter {
        qobject: Arc::new(AtomicPtr::new(todos)),
        active_count_changed: todos_active_count_changed,
        count_changed: todos_count_changed,
        new_data_ready: todos_new_data_ready,
    };
    let model = TodosList {
        qobject: todos,
        layout_about_to_be_changed: todos_layout_about_to_be_changed,
        layout_changed: todos_layout_changed,
        data_changed: todos_data_changed,
        begin_reset_model: todos_begin_reset_model,
        end_reset_model: todos_end_reset_model,
        begin_insert_rows: todos_begin_insert_rows,
        end_insert_rows: todos_end_insert_rows,
        begin_move_rows: todos_begin_move_rows,
        end_move_rows: todos_end_move_rows,
        begin_remove_rows: todos_begin_remove_rows,
        end_remove_rows: todos_end_remove_rows,
    };
    let d_todos = Todos::new(todos_emit, model);
    Box::into_raw(Box::new(d_todos))
}

#[no_mangle]
pub unsafe extern "C" fn todos_free(ptr: *mut Todos) {
    Box::from_raw(ptr).emit().clear();
}

#[no_mangle]
pub unsafe extern "C" fn todos_active_count_get(ptr: *const Todos) -> u64 {
    (&*ptr).active_count()
}

#[no_mangle]
pub unsafe extern "C" fn todos_count_get(ptr: *const Todos) -> u64 {
    (&*ptr).count()
}

#[no_mangle]
pub unsafe extern "C" fn todos_add(ptr: *mut Todos, description_str: *const c_ushort, description_len: c_int) -> () {
    let mut description = String::new();
    set_string_from_utf16(&mut description, description_str, description_len);
    let o = &mut *ptr;
    let r = o.add(description);
    r
}

#[no_mangle]
pub unsafe extern "C" fn todos_clear_completed(ptr: *mut Todos) -> () {
    let o = &mut *ptr;
    let r = o.clear_completed();
    r
}

#[no_mangle]
pub unsafe extern "C" fn todos_remove(ptr: *mut Todos, index: u64) -> bool {
    let o = &mut *ptr;
    let r = o.remove(index);
    r
}

#[no_mangle]
pub unsafe extern "C" fn todos_set_all(ptr: *mut Todos, completed: bool) -> () {
    let o = &mut *ptr;
    let r = o.set_all(completed);
    r
}

#[no_mangle]
pub unsafe extern "C" fn todos_row_count(ptr: *const Todos) -> c_int {
    to_c_int((&*ptr).row_count())
}
#[no_mangle]
pub unsafe extern "C" fn todos_insert_rows(ptr: *mut Todos, row: c_int, count: c_int) -> bool {
    (&mut *ptr).insert_rows(to_usize(row), to_usize(count))
}
#[no_mangle]
pub unsafe extern "C" fn todos_remove_rows(ptr: *mut Todos, row: c_int, count: c_int) -> bool {
    (&mut *ptr).remove_rows(to_usize(row), to_usize(count))
}
#[no_mangle]
pub unsafe extern "C" fn todos_can_fetch_more(ptr: *const Todos) -> bool {
    (&*ptr).can_fetch_more()
}
#[no_mangle]
pub unsafe extern "C" fn todos_fetch_more(ptr: *mut Todos) {
    (&mut *ptr).fetch_more()
}
#[no_mangle]
pub unsafe extern "C" fn todos_sort(
    ptr: *mut Todos,
    column: u8,
    order: SortOrder,
) {
    (&mut *ptr).sort(column, order)
}

#[no_mangle]
pub unsafe extern "C" fn todos_data_completed(ptr: *const Todos, row: c_int) -> bool {
    let o = &*ptr;
    o.completed(to_usize(row)).into()
}

#[no_mangle]
pub unsafe extern "C" fn todos_set_data_completed(
    ptr: *mut Todos, row: c_int,
    v: bool,
) -> bool {
    (&mut *ptr).set_completed(to_usize(row), v)
}

#[no_mangle]
pub unsafe extern "C" fn todos_data_description(
    ptr: *const Todos, row: c_int,
    d: *mut QString,
    set: fn(*mut QString, *const c_char, len: c_int),
) {
    let o = &*ptr;
    let data = o.description(to_usize(row));
    let s: *const c_char = data.as_ptr() as (*const c_char);
    set(d, s, to_c_int(data.len()));
}

#[no_mangle]
pub unsafe extern "C" fn todos_set_data_description(
    ptr: *mut Todos, row: c_int,
    s: *const c_ushort, len: c_int,
) -> bool {
    let o = &mut *ptr;
    let mut v = String::new();
    set_string_from_utf16(&mut v, s, len);
    o.set_description(to_usize(row), v)
}